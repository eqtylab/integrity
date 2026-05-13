//! Adapter that plugs `integrity_signer::SignerType` into ssi 0.16's
//! `Signer<M>` / `MessageSigner<A>` machinery so any of our 8 signer backends
//! (Ed25519/P-256/secp256k1 in-memory + AKV/YubiKey/YubiHSM/AuthService/
//! VCompNotary/SLH-DSA) can drive a `ssi-data-integrity` cryptosuite.
//!
//! Our backends expose `async fn sign(&[u8]) -> Result<[u8; 64]>`; ssi 0.16
//! expects a typed verification-method-aware signer that produces
//! `Vec<u8>`. The two adapters here bridge that gap.

use std::borrow::Cow;

use anyhow::{anyhow, Result};
use integrity_signer::SignerType;
use ssi::{
    claims::{data_integrity::AnySuite, MessageSignatureError, SignatureError},
    crypto::algorithm::SignatureAlgorithmType,
    jwk::JWK,
    verification_methods::{MessageSigner, Signer, VerificationMethod},
};

/// Wraps a `SignerType` so it can be passed to `<AnySuite>.sign(...)`.
pub(crate) struct IntegritySigner {
    inner: SignerType,
}

impl IntegritySigner {
    pub fn new(inner: SignerType) -> Self {
        Self { inner }
    }

    /// Returns the verification-method IRI for the signer's DID. Used as the
    /// `verification_method` in `ProofOptions`.
    pub fn verification_method_iri(&self) -> Result<iref::IriBuf> {
        let did_doc = self.inner.get_did_doc();
        let vm = did_doc
            .verification_method
            .first()
            .ok_or_else(|| anyhow!("DID document has no verification method"))?;
        iref::IriBuf::new(vm.id.clone())
            .map_err(|e| anyhow!("invalid verification method IRI: {e}"))
    }

    /// Returns the issuer DID's URI form. Used as the credential's `issuer`.
    pub fn issuer_uri(&self) -> Result<iref::UriBuf> {
        let did_doc = self.inner.get_did_doc();
        iref::UriBuf::new(did_doc.id.into_bytes()).map_err(|e| anyhow!("invalid issuer URI: {e:?}"))
    }

    /// Picks the cryptosuite for the signer's key curve.
    ///
    /// Uses the v1-era suites (`Ed25519Signature2018`,
    /// `EcdsaSecp256r1Signature2019`, `EcdsaSecp256k1Signature2019`) to keep
    /// the on-the-wire proof shape compatible with downstream verifiers
    /// built against ssi 0.7-era output. Their proof terms live in the
    /// `https://w3id.org/security/v2` context, which `build_unsigned` adds
    /// to the credential's `@context`.
    pub fn suite(&self) -> Result<AnySuite> {
        let did_doc = self.inner.get_did_doc();
        let jwk = jwk_from_did_doc(&did_doc)?;
        match jwk.get_algorithm() {
            Some(ssi::jwk::Algorithm::EdDSA) => Ok(AnySuite::Ed25519Signature2018),
            Some(ssi::jwk::Algorithm::ES256) => Ok(AnySuite::EcdsaSecp256r1Signature2019),
            Some(ssi::jwk::Algorithm::ES256K) => Ok(AnySuite::EcdsaSecp256k1Signature2019),
            other => Err(anyhow!(
                "no VC cryptosuite for signer key algorithm: {other:?}"
            )),
        }
    }
}

impl<M: VerificationMethod> Signer<M> for IntegritySigner {
    type MessageSigner = IntegrityMessageSigner;

    async fn for_method(
        &self,
        _method: Cow<'_, M>,
    ) -> std::result::Result<Option<Self::MessageSigner>, SignatureError> {
        Ok(Some(IntegrityMessageSigner {
            inner: self.inner.clone(),
        }))
    }
}

/// Per-message signer handed out by `IntegritySigner::for_method`.
pub(crate) struct IntegrityMessageSigner {
    inner: SignerType,
}

impl<A: SignatureAlgorithmType> MessageSigner<A> for IntegrityMessageSigner {
    async fn sign(
        self,
        _algorithm: A::Instance,
        message: &[u8],
    ) -> std::result::Result<Vec<u8>, MessageSignatureError> {
        // Our SignerType ignores the algorithm parameter — each backend was
        // constructed knowing its own key type, and ssi picks the matching
        // cryptosuite via `IntegritySigner::suite()`. Hand the raw bytes off
        // and pass back the 64-byte signature as a Vec.
        let sig = self
            .inner
            .sign(message)
            .await
            .map_err(|e| MessageSignatureError::signature_failed(format!("{e}")))?;
        Ok(sig.to_vec())
    }
}

/// Convert the `did_key::JWK` produced by signer backends into an `ssi::JWK`
/// via JSON round-tripping. This is the same trick the old code used at
/// `integrity-vc/src/lib.rs:441` and is needed because the two crate
/// hierarchies have separate JWK type definitions.
fn jwk_from_did_doc(did_doc: &did_key::Document) -> Result<JWK> {
    use did_key::KeyFormat;
    let vm = did_doc
        .verification_method
        .first()
        .ok_or_else(|| anyhow!("DID document has no verification method"))?;
    match &vm.public_key {
        Some(KeyFormat::JWK(jwk)) => {
            let v = serde_json::to_value(jwk)?;
            Ok(serde_json::from_value::<JWK>(v)?)
        }
        _ => Err(anyhow!(
            "verification method does not carry a JWK public key"
        )),
    }
}
