//! Opt-in Guardian F3 signing. A signer holds one metadata snapshot for its lifetime.

use std::{fmt, time::Duration};

use anyhow::{anyhow, bail, Result};
use async_trait::async_trait;
use did_key::{Document, KeyFormat};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::Signer;

/// Auth-authorized key purpose. User and service-account tokens use `Did`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthSigningPurpose {
    /// The authenticated user's or service account's DID key.
    #[serde(rename = "did")]
    Did,
    /// The shared platform DID key, subject to Auth's role checks.
    #[serde(rename = "platform-did")]
    Platform,
}

impl AuthSigningPurpose {
    fn route(self) -> &'static str {
        match self {
            Self::Did => "api/v1/protected",
            Self::Platform => "api/v1/protected/platform",
        }
    }
}

/// A fail-closed Auth signer bound to one owner, purpose and key version.
///
/// Unlike [`super::AuthServiceSigner`], this requires Guardian's F3 metadata and
/// echoed-reference contract. It never refreshes metadata, retries signing, or
/// falls back to legacy signing. Dropping the future cancels client-side work;
/// a request already received by Auth may still have signed.
#[derive(Clone, Serialize, Deserialize)]
pub struct BoundAuthServiceSigner {
    api_key: String,
    url: String,
    purpose: AuthSigningPurpose,
    metadata: SigningKeyMetadata,
    timeout_ms: u64,
}

impl fmt::Debug for BoundAuthServiceSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BoundAuthServiceSigner")
            .field("purpose", &self.purpose)
            .field("did", &self.metadata.did_document.id)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SigningKeyMetadata {
    signing_key_reference: String,
    algorithm: String,
    purpose: AuthSigningPurpose,
    hash_algorithm: String,
    signature_encoding: String,
    jose_algorithm: String,
    did_document: Document,
}

impl BoundAuthServiceSigner {
    /// Fetches metadata from an Auth base URL with a ten-second request deadline.
    pub async fn create(api_key: String, url: String, purpose: AuthSigningPurpose) -> Result<Self> {
        Self::create_with_timeout(api_key, url, purpose, Duration::from_secs(10)).await
    }

    /// Like [`Self::create`], with a nonzero total deadline for each HTTP request,
    /// including its response body. The URL is the Auth base, without `/platform`.
    pub async fn create_with_timeout(
        api_key: String,
        url: String,
        purpose: AuthSigningPurpose,
        timeout: Duration,
    ) -> Result<Self> {
        let timeout_ms = u64::try_from(timeout.as_millis())?;
        let client = client(timeout_ms)?;
        let response = client
            .get(format!(
                "{}/{}/signing-key",
                url.trim_end_matches('/'),
                purpose.route()
            ))
            .bearer_auth(&api_key)
            .send()
            .await?;
        require_success(response.status())?;
        let signer = Self {
            api_key,
            url,
            purpose,
            metadata: response.json().await?,
            timeout_ms,
        };
        signer.validate()?;
        Ok(signer)
    }

    /// The immutable public identity used to construct proofs.
    pub fn did_document(&self) -> &Document {
        &self.metadata.did_document
    }

    /// The opaque reference returned by Auth, retained exactly as received.
    pub fn signing_key_reference(&self) -> &str {
        &self.metadata.signing_key_reference
    }

    fn validate(&self) -> Result<()> {
        let metadata = &self.metadata;
        let curve = match (
            metadata.algorithm.as_str(),
            metadata.jose_algorithm.as_str(),
        ) {
            ("p256", "ES256") => "P-256",
            ("secp256k1", "ES256K") => "secp256k1",
            _ => bail!("unsupported Auth signing profile"),
        };
        if metadata.signing_key_reference.trim().is_empty()
            || metadata.purpose != self.purpose
            || metadata.hash_algorithm != "SHA-256"
            || metadata.signature_encoding != "ieee-p1363"
        {
            bail!("incompatible Auth signing metadata");
        }
        let doc = &metadata.did_document;
        let vm = doc
            .verification_method
            .first()
            .ok_or_else(|| anyhow!("missing verification method"))?;
        let Some(KeyFormat::JWK(jwk)) = &vm.public_key else {
            bail!("Auth signing metadata requires a public JWK");
        };
        if !doc.id.starts_with("did:key:")
            || vm.controller != doc.id
            || !vm.id.starts_with(&format!("{}#", doc.id))
            || jwk.key_type != "EC"
            || jwk.curve != curve
            || jwk.x.is_none()
            || jwk.y.is_none()
            || jwk.d.is_some()
            || vm.private_key.is_some()
        {
            bail!("incompatible Auth signing DID document");
        }
        Ok(())
    }
}

fn client(timeout_ms: u64) -> Result<Client> {
    if timeout_ms == 0 {
        bail!("Auth signing timeout must be at least one millisecond");
    }
    Ok(Client::builder()
        .timeout(Duration::from_millis(timeout_ms))
        .redirect(reqwest::redirect::Policy::none())
        .build()?)
}

fn require_success(status: reqwest::StatusCode) -> Result<()> {
    if !status.is_success() {
        // Server bodies may contain credentials or provider details.
        bail!("bound Auth signing request failed with status {status}");
    }
    Ok(())
}

#[async_trait]
impl Signer for BoundAuthServiceSigner {
    async fn sign(&self, data: &[u8]) -> Result<[u8; 64]> {
        // Also validate deserialized configurations. Missing bound fields never
        // deserialize as a legacy signer, and errors never change this snapshot.
        self.validate()?;
        let response = client(self.timeout_ms)?
            .post(format!(
                "{}/{}/sign",
                self.url.trim_end_matches('/'),
                self.purpose.route()
            ))
            .bearer_auth(&self.api_key)
            .json(&serde_json::json!({
                "dataHash": hex::encode(Sha256::digest(data)),
                "signingKeyReference": self.metadata.signing_key_reference,
            }))
            .send()
            .await?;
        require_success(response.status())?;
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Response {
            signature: String,
            signing_key_reference: String,
        }
        let response: Response = response.json().await?;
        if response.signing_key_reference != self.metadata.signing_key_reference {
            bail!("Auth response signing key reference does not match metadata");
        }
        hex::decode(response.signature)?
            .try_into()
            .map_err(|sig: Vec<u8>| anyhow!("signature must be 64 bytes, received {}", sig.len()))
    }

    async fn get_did_doc(&self) -> Result<Option<Document>> {
        self.validate()?;
        Ok(Some(self.metadata.did_document.clone()))
    }
}
