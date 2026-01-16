use anyhow::{anyhow, Result};
use async_trait::async_trait;
use did_key::{CoreSign, DIDCore, Document, Ed25519KeyPair, Generate, KeyMaterial};
use serde::{Deserialize, Serialize};

use crate::signer::Signer;

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct Ed25519Signer {
    secret_key: Vec<u8>,
    pub did_doc: Document,
}

impl Ed25519Signer {
    pub fn create() -> Result<Self> {
        let key_pair = Ed25519KeyPair::new();
        let did_doc = key_pair.get_did_document(did_key::Config {
            use_jose_format: true,
            serialize_secrets: true,
        });
        let signer = Ed25519Signer {
            secret_key: key_pair.private_key_bytes(),
            did_doc,
        };
        Ok(signer)
    }

    pub fn import(secret_key: &[u8]) -> Result<Self> {
        let key_pair = Ed25519KeyPair::from_secret_key(secret_key);
        let did_doc = key_pair.get_did_document(did_key::Config {
            use_jose_format: true,
            serialize_secrets: true,
        });
        let signer = Ed25519Signer {
            secret_key: secret_key.to_vec(),
            did_doc,
        };
        Ok(signer)
    }
}

#[async_trait]
impl Signer for Ed25519Signer {
    async fn sign(&self, data: &[u8]) -> Result<[u8; 64]> {
        log::trace!("Signing data with Ed25519 key");
        let keypair = Ed25519KeyPair::from_secret_key(&self.secret_key);
        let sig = keypair.sign(data);
        let sig_array = sig
            .try_into()
            .map_err(|_| anyhow!("Signature must be 64 bytes"))?;
        Ok(sig_array)
    }

    async fn get_did_doc(&self) -> Result<Option<Document>> {
        Ok(Some(self.did_doc.clone()))
    }
}
