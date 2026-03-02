/// Serialization models for in-toto attestations.
pub mod models;

/// Predicate types and handling for attestation claims.
pub mod predicate;

/// Statement structures for in-toto attestations.
pub mod statement;

/// Subject definitions for attested artifacts.
pub mod subject;

use std::{collections::HashMap, sync::Arc};

use anyhow::{anyhow, Result};
use base64::engine::{general_purpose::STANDARD as BASE64, Engine};
use did_key::CoreSign;
use integrity_signer::Signer;
/// Re-exported predicate types for convenience.
pub use predicate::{Predicate, PredicateType};
use serde::{Deserialize, Serialize};
/// Re-exported statement type for convenience.
pub use statement::Statement;
/// Re-exported subject type for convenience.
pub use subject::Subject;

const SHA2_256_MULTIHASH: u64 = 0x12;
const BLAKE3_MULTIHASH: u64 = 0x1e;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DsseEnvelope {
    payload_type: String,
    payload: String,
    signatures: Vec<DsseSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DsseSignature {
    keyid: String,
    sig: String,
}

/// Signs an in-toto attestation statement using the active signer.
///
/// # Arguments
/// * `statement` - in-toto statement to sign
///
/// # Returns
/// * `Result<String>` - JSON string of signed DSSE envelope, or error if signing fails
pub async fn sign_intoto_attestation(
    statement: Statement,
    signer: Arc<dyn Signer>,
) -> Result<String> {
    let payload = statement.into_json_string()?.as_bytes().to_vec();

    let keyid = signer
        .get_did_doc()
        .await?
        .map(|d| d.id)
        .ok_or_else(|| anyhow!("No DID Document for signer."))?;

    let media_type = "application/vnd.in-toto+json";
    let msg = format!(
        "DSSEv1 {} {} {} {}",
        media_type.len(),
        media_type,
        payload.len(),
        String::from_utf8(payload.clone())?
    );

    let sig = signer.sign(msg.as_bytes()).await?;
    let sig = p256::ecdsa::Signature::from_slice(&sig)
        .map_err(|e| anyhow!("Failed to parse signature: {e}"))?;
    let sig = sig.to_der().as_bytes().to_vec();

    let envelope = DsseEnvelope {
        payload_type: media_type.to_owned(),
        payload: BASE64.encode(payload),
        signatures: vec![DsseSignature {
            keyid,
            sig: BASE64.encode(sig),
        }],
    };

    let envelope = serde_json::to_string(&envelope)?;
    Ok(envelope)
}

/// Verifies an in-toto attestation DSSE envelope.
///
/// # Arguments
/// * `envelope` - JSON string of DSSE envelope to verify
///
/// # Returns
/// * `Result<bool>` - True if all signatures are valid, false otherwise, or error if verification fails
pub async fn verify_intoto_attestation(envelope: &str) -> Result<bool> {
    let envelope: DsseEnvelope = serde_json::from_str(envelope)?;

    if envelope.signatures.is_empty() {
        return Ok(false);
    }

    let payload = BASE64.decode(envelope.payload)?;

    for signature in envelope.signatures {
        let did = did_key::PatchedKeyPair::try_from(signature.keyid.as_str()).expect("TODO");
        let sig = BASE64.decode(signature.sig)?;

        if let Err(_err) = did.verify(&payload, &sig) {
            return Ok(false);
        }
    }

    Ok(true)
}

/// Creates a digest map from a CID string, extracting hash information.
///
/// # Arguments
/// * `cid_str` - CID string to extract digest from
///
/// # Returns
/// * `Result<HashMap<String, String>>` - Map containing CID and hash digests, or error if CID is invalid
pub fn digest_from_cid(cid_str: &str) -> Result<HashMap<String, String>> {
    let cid = cid_str.parse::<cid::Cid>()?;

    let mut digest = HashMap::new();

    digest.insert("cid".to_owned(), cid_str.to_owned());

    match cid.hash().code() {
        SHA2_256_MULTIHASH => {
            digest.insert("sha256".to_owned(), hex::encode(cid.hash().digest()));
        }
        BLAKE3_MULTIHASH => {
            digest.insert("blake3".to_owned(), hex::encode(cid.hash().digest()));
        }
        _ => {}
    }

    Ok(digest)
}
