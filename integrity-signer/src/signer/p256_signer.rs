use anyhow::{anyhow, Result};
use async_trait::async_trait;
use did_key::{CoreSign, DIDCore, Document, Generate, KeyMaterial, P256KeyPair};
use serde::{Deserialize, Serialize};

use crate::signer::{
    p256_jwk::{fix_p256_jwk_from_encoded_point, p256_encoded_point_from_secret_key},
    Signer,
};

/// Signer implementation using P-256 (secp256r1) elliptic curve.
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct P256Signer {
    secret_key: Vec<u8>,
    /// DID document derived from the P-256 public key
    pub did_doc: Document,
}

impl P256Signer {
    /// Creates a new P256Signer instance with a randomly generated key pair.
    ///
    /// # Returns
    ///
    /// A new `P256Signer` with the DID document derived from the generated key pair.
    pub fn create() -> Result<Self> {
        let key_pair = P256KeyPair::new();
        let mut did_doc = key_pair.get_did_document(did_key::Config {
            use_jose_format: true,
            serialize_secrets: false,
        });
        // Fix the JWK to include both x and y coordinates (did-key bug workaround)
        fix_p256_jwk(&mut did_doc, &key_pair.private_key_bytes())?;
        let signer = P256Signer {
            secret_key: key_pair.private_key_bytes(),
            did_doc,
        };
        Ok(signer)
    }

    /// Imports a P256Signer instance from a given secret key.
    ///
    /// # Arguments
    ///
    /// * `secret_key` - The secret key bytes to import.
    ///
    /// # Returns
    ///
    /// A new `P256Signer` with the DID document derived from the provided secret key.
    pub fn import(secret_key: &[u8]) -> Result<Self> {
        let key_pair = P256KeyPair::from_secret_key(secret_key);
        let mut did_doc = key_pair.get_did_document(did_key::Config {
            use_jose_format: true,
            serialize_secrets: false,
        });
        // Fix the JWK to include both x and y coordinates (did-key bug workaround)
        fix_p256_jwk(&mut did_doc, secret_key)?;
        let signer = P256Signer {
            secret_key: secret_key.to_vec(),
            did_doc,
        };
        Ok(signer)
    }
}

/// Fix the P-256 JWK in the DID document to include both x and y coordinates.
///
/// The did-key crate has a bug where it puts the compressed public key in the x field
/// and omits the y field. This function extracts the correct x and y coordinates from
/// the uncompressed public key and updates the JWK.
fn fix_p256_jwk(did_doc: &mut Document, secret_key: &[u8]) -> Result<()> {
    let encoded_point = p256_encoded_point_from_secret_key(secret_key)?;
    fix_p256_jwk_from_encoded_point(did_doc, &encoded_point, Some(secret_key))
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
