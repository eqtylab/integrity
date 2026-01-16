use anyhow::{anyhow, Result};
use async_trait::async_trait;
use did_key::{CoreSign, DIDCore, Document, Generate, KeyMaterial, P256KeyPair};
use serde::{Deserialize, Serialize};

use crate::signer::Signer;

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct P256Signer {
    secret_key: Vec<u8>,
    pub did_doc: Document,
}

impl P256Signer {
    /// Creates a new P256Signer instance.
    /// This function generates a new P256Signer key pair and constructs a signer with the DID document derived from this key pair.
    /// @return {`Result<P256Signer>`} - The created P256Signer instance or an error if creation fails.
    pub fn create() -> Result<Self> {
        let key_pair = P256KeyPair::new();
        let did_doc = key_pair.get_did_document(did_key::Config {
            use_jose_format: true,
            serialize_secrets: true,
        });
        let signer = P256Signer {
            secret_key: key_pair.private_key_bytes(),
            did_doc,
        };
        Ok(signer)
    }

    /// Imports a P256Signer instance from a given secret key.
    /// This function constructs a signer with the DID document derived from the provided secret key.
    /// @param {&[u8]} secret_key - The byte slice representing the secret key of the imported key pair.
    /// @return {`Result<P256Signer>`} - The created P256Signer instance or an error if import fails.
    pub fn import(secret_key: &[u8]) -> Result<Self> {
        let key_pair = P256KeyPair::from_secret_key(secret_key);
        let did_doc = key_pair.get_did_document(did_key::Config {
            use_jose_format: true,
            serialize_secrets: true,
        });
        let signer = P256Signer {
            secret_key: secret_key.to_vec(),
            did_doc,
        };
        Ok(signer)
    }
}

#[async_trait]
impl Signer for P256Signer {
    async fn sign(&self, data: &[u8]) -> Result<[u8; 64]> {
        log::trace!("Signing data with P256 key");
        let keypair = P256KeyPair::from_secret_key(&self.secret_key);
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
