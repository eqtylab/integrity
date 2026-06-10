//! In-process signer that delegates raw P-256 signing to a host-provided
//! closure (e.g. the notary daemon's keystore), while deriving its DID
//! document from a notary-supplied compressed SEC1 public key.
//!
//! Unlike [`crate::signer::VCompNotarySigner`], which signs by making a network
//! call to a notary `/v1/sign` endpoint, this signer calls straight into the
//! host. It is used when the proxy runs *inside* the notary process and must
//! sign with a specific binary's key without a network round-trip or PID
//! re-resolution — the caller has already been authorized out-of-band.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use did_key::{DIDCore, Document, Generate, P256KeyPair};

use crate::signer::{
    p256_jwk::{fix_p256_jwk_from_encoded_point, p256_encoded_point_from_public_key},
    Signer,
};

/// Boxed future returned by an [`InProcSignFn`].
pub type SignFuture = Pin<Box<dyn Future<Output = Result<[u8; 64]>> + Send>>;

/// Host-provided signing callback: given the bytes to sign, returns a raw
/// 64-byte (R||S) P-256 signature.
pub type InProcSignFn = Arc<dyn Fn(Vec<u8>) -> SignFuture + Send + Sync>;

/// Signer that derives its DID from a compressed P-256 public key and
/// delegates the actual signing to an in-process callback.
///
/// Carries a closure, so it is intentionally **not** `Serialize`/`Deserialize`
/// (the enclosing `SignerType` variant is `#[serde(skip)]`) — instances are
/// constructed at runtime and never persisted.
#[derive(Clone)]
pub struct NotaryInProcSigner {
    /// DID document derived from the notary public key.
    pub did_doc: Document,
    /// SEC1-compressed P-256 public key, lower-case hex.
    pub public_key: String,
    /// In-process signing callback.
    sign_fn: InProcSignFn,
}

impl fmt::Debug for NotaryInProcSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NotaryInProcSigner")
            .field("did", &self.did_doc.id)
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

impl NotaryInProcSigner {
    /// Build a signer from a compressed SEC1 P-256 public key (33 bytes) and a
    /// signing callback. The DID document is derived to match what
    /// [`crate::signer::VCompNotarySigner`] produces for the same key.
    pub fn from_p256_compressed(compressed_sec1: &[u8], sign_fn: InProcSignFn) -> Result<Self> {
        let did_doc = did_doc_from_public_key(compressed_sec1)?;
        Ok(Self {
            did_doc,
            public_key: hex::encode(compressed_sec1),
            sign_fn,
        })
    }
}

fn did_doc_from_public_key(pub_key: &[u8]) -> Result<Document> {
    let key_pair = P256KeyPair::from_public_key(pub_key);
    let mut did_doc = key_pair.get_did_document(did_key::Config {
        use_jose_format: true,
        serialize_secrets: false,
    });
    let encoded_point = p256_encoded_point_from_public_key(pub_key)?;
    fix_p256_jwk_from_encoded_point(&mut did_doc, &encoded_point, None)?;
    Ok(did_doc)
}

#[async_trait]
impl Signer for NotaryInProcSigner {
    async fn sign(&self, data: &[u8]) -> Result<[u8; 64]> {
        (self.sign_fn)(data.to_vec()).await
    }

    async fn get_did_doc(&self) -> Result<Option<Document>> {
        Ok(Some(self.did_doc.clone()))
    }
}
