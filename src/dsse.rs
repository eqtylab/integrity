use std::{convert::TryFrom, fmt, str::FromStr, sync::Arc};

use anyhow::{anyhow, bail, Result};
use base64::engine::{general_purpose::STANDARD as BASE64, Engine};

use crate::{alt_signer::AltSigner, lineage::models, signer::Signer};

/// Dead Simple Signing Envelope (DSSE) for secure payload signatures.
///
/// DSSE provides a simple, standardized way to sign arbitrary payloads
/// with one or more digital signatures, commonly used in software supply chain security.
#[derive(Debug, Clone)]
pub struct Envelope {
    /// The type/format of the payload being signed
    pub payload_type: PayloadType,
    /// The raw payload data in bytes
    pub payload: Vec<u8>,
    /// One or more digital signatures for the payload
    pub signatures: Vec<Signature>,
}

impl Envelope {
    /// Converts the envelope into a JSON string representation.
    ///
    /// # Returns
    /// * `Result<String>` - JSON string of the envelope, or error if serialization fails
    pub fn into_json_string(self) -> Result<String> {
        let envelope = models::dsse::Envelope::from(self);
        let s = serde_json::to_string(&envelope)?;

        Ok(s)
    }

    /// Creates an envelope from a JSON string representation.
    ///
    /// # Arguments
    /// * `s` - JSON string to parse
    ///
    /// # Returns
    /// * `Result<Self>` - Parsed envelope, or error if deserialization fails
    pub fn try_from_json_string(s: &str) -> Result<Self> {
        let envelope: models::dsse::Envelope = serde_json::from_str(s)?;
        Self::try_from(envelope)
    }
}

/// Supported payload types for DSSE envelopes.
///
/// Defines the content type and format of the payload being signed,
/// enabling proper verification and interpretation of the signed data.
#[derive(Debug, Clone)]
pub enum PayloadType {
    /// in-toto attestation in JSON format
    InTotoJson,
    /// Integrity statement URN reference
    IntegrityStatementUrn,
    /// Any other custom payload type
    Other(String),
}

impl fmt::Display for PayloadType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PayloadType::InTotoJson => write!(f, "application/vnd.in-toto+json"),
            PayloadType::IntegrityStatementUrn => {
                write!(f, "https://eqtylab.io/terms/IntegrityStatementUrn")
            }
            PayloadType::Other(s) => write!(f, "{}", s),
        }
    }
}

impl FromStr for PayloadType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "application/vnd.in-toto+json" => Ok(PayloadType::InTotoJson),
            "https://eqtylab.io/terms/IntegrityStatementUrn" => {
                Ok(PayloadType::IntegrityStatementUrn)
            }
            _ => Ok(PayloadType::Other(s.to_owned())),
        }
    }
}

/// Digital signature within a DSSE envelope.
///
/// Contains the signature bytes and key identifier for verification,
/// allowing multiple signatures from different signers on the same payload.
#[derive(Debug, Clone)]
pub struct Signature {
    /// Key identifier used to create the signature
    pub keyid: String,
    /// The actual signature bytes
    pub sig: Vec<u8>,
}

/// Signs a payload using DSSE (Dead Simple Signing Envelope) format.
///
/// # Arguments
/// * `payload` - Data bytes to sign
/// * `payload_type` - Type/format of the payload
/// * `alt_signer` - Optional alternative signer (uses active signer if None)
///
/// # Returns
/// * `Result<Envelope>` - Signed DSSE envelope, or error if signing fails
pub async fn sign_dsse(
    payload: Vec<u8>,
    payload_type: PayloadType,
    signer: Option<Arc<dyn Signer>>,
    alt_signer: Option<AltSigner>,
) -> Result<Envelope> {
    let signature = match (signer, alt_signer) {
        (Some(signer), None) => {
            let keyid = signer
                .get_did_doc()
                .await?
                .map(|d| d.id)
                .ok_or_else(|| anyhow!("No DID Document for signer."))?;
            let sig = signer.sign(&payload).await?.to_vec();

            Signature { keyid, sig }
        }
        (None, Some(alt_signer)) => {
            let keyid = alt_signer.keyid()?;
            let sig = alt_signer.sign(&payload)?;

            Signature { keyid, sig }
        }
        (Some(_), Some(_)) => {
            bail!("Cannot provide both a standard signer and an alternative signer.");
        }
        (None, None) => {
            bail!("Either a standard signer or an alternative signer must be provided.");
        }
    };

    let signatures = vec![signature];

    let envelope = Envelope {
        payload_type,
        payload,
        signatures,
    };

    Ok(envelope)
}

/// Signs an integrity statement CID using DSSE format.
///
/// # Arguments
/// * `statement_cid` - CID of the integrity statement to sign
/// * `alt_signer` - Optional alternative signer (uses active signer if None)
///
/// # Returns
/// * `Result<Envelope>` - Signed DSSE envelope containing the statement URN, or error if signing fails
pub async fn sign_integrity_statement_dsse(
    statement_cid: String,
    signer: Option<Arc<dyn Signer>>,
    alt_signer: Option<AltSigner>,
) -> Result<Envelope> {
    let payload_type = PayloadType::IntegrityStatementUrn;

    let statement_urn = format!("urn:cid:{}", statement_cid);

    let payload = statement_urn.as_bytes().to_vec();

    let envelope = sign_dsse(payload, payload_type, signer, alt_signer).await?;

    Ok(envelope)
}

/// Verifies a DSSE envelope signature (currently not implemented).
///
/// # Arguments
/// * `envelope` - DSSE envelope string to verify
///
/// # Returns
/// * `Result<bool>` - True if signature is valid, false otherwise, or error if verification fails
pub async fn verify_dsse(envelope: &str) -> Result<bool> {
    let _ = envelope;
    todo!("Implement verify_dsse()");
}

impl TryFrom<models::dsse::Envelope> for Envelope {
    type Error = anyhow::Error;

    fn try_from(envelope: models::dsse::Envelope) -> Result<Self> {
        let models::dsse::Envelope {
            payload_type,
            payload,
            signatures,
        } = envelope;

        let payload_type = PayloadType::from_str(&payload_type)?;

        let payload = BASE64.decode(payload)?;

        let signatures = signatures
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>>>()?;

        Ok(Self {
            payload_type,
            payload,
            signatures,
        })
    }
}

impl From<Envelope> for models::dsse::Envelope {
    fn from(envelope: Envelope) -> Self {
        let Envelope {
            payload_type,
            payload,
            signatures,
        } = envelope;

        let payload_type = payload_type.to_string();
        let payload = BASE64.encode(payload);
        let signatures = signatures.into_iter().map(Into::into).collect();

        Self {
            payload_type,
            payload,
            signatures,
        }
    }
}

impl TryFrom<models::dsse::Signature> for Signature {
    type Error = anyhow::Error;

    fn try_from(signature: models::dsse::Signature) -> Result<Self> {
        let models::dsse::Signature { keyid, sig } = signature;

        let sig = BASE64.decode(sig)?;

        Ok(Self { keyid, sig })
    }
}

impl From<Signature> for models::dsse::Signature {
    fn from(signature: Signature) -> Self {
        let Signature { keyid, sig } = signature;

        let sig = BASE64.encode(sig);

        Self { keyid, sig }
    }
}
