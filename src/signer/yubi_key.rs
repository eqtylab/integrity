use anyhow::{anyhow, Result};
use async_trait::async_trait;
use did_key::{DIDCore, Document, Ed25519KeyPair};
use serde::{Deserialize, Serialize};
use yubihsm::{asymmetric::signature::Signer as _, UsbConfig};

use crate::signer::Signer;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct YubiHsmSigner {
    pub auth_key_id: u16,
    pub signing_key_id: u16,
    pub password: String,
    pub did_doc: Document,
}

impl YubiHsmSigner {
    /// Creates a new YubiHsmSigner instance.
    /// This function generates a new YubiHsmSigner key pair and constructs a signer with the DID document derived from this key pair.
    /// @return {`Result<YubiHsmSigner>`} - The created YubiHsmSigner instance or an error if creation fails.
    pub fn create(auth_key_id: u16, signing_key_id: u16, password: String) -> Result<Self> {
        let connector = yubihsm::Connector::usb(&UsbConfig::default());
        let credentials = yubihsm::Credentials::from_password(auth_key_id, password.as_bytes());
        let client = yubihsm::Client::open(connector, credentials, true)?;
        let signer = yubihsm::ed25519::Signer::create(client, signing_key_id)?;

        let pub_key = signer.public_key().into_bytes().to_vec();
        let key_pair = Ed25519KeyPair::from_public_key(&pub_key);
        let did_doc = key_pair.get_did_document(did_key::Config {
            use_jose_format: true,
            serialize_secrets: true,
        });

        Ok(YubiHsmSigner {
            auth_key_id,
            signing_key_id,
            password,
            did_doc,
        })
    }
}

#[async_trait]
impl Signer for YubiHsmSigner {
    async fn sign(&self, data: &[u8]) -> Result<[u8; 64]> {
        let connector = yubihsm::Connector::usb(&UsbConfig::default());
        let credentials =
            yubihsm::Credentials::from_password(self.auth_key_id, self.password.as_bytes());
        let client = yubihsm::Client::open(connector, credentials, true)?;
        let signer = yubihsm::ed25519::Signer::create(client, self.signing_key_id)?;
        let sig = signer.try_sign(data)?.to_vec();

        let sig = sig
            .clone()
            .try_into()
            .map_err(|_| anyhow!("Signature is not 64 bytes: legth = {}", sig.len()))?;

        Ok(sig)
    }

    async fn get_did_doc(&self) -> Result<Option<Document>> {
        Ok(Some(self.did_doc.clone()))
    }
}
