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
use did_key::CoreSign;
/// Re-exported predicate types for convenience.
pub use predicate::{Predicate, PredicateType};
/// Re-exported statement type for convenience.
pub use statement::Statement;
/// Re-exported subject type for convenience.
pub use subject::Subject;

use crate::{
    cid::multihash,
    dsse::{Envelope, PayloadType, Signature},
    signer::Signer,
};

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
    let payload_type = PayloadType::InTotoJson;

    let payload = statement.into_json_string()?.as_bytes().to_vec();

    let signatures = {
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
        let sig = p256::ecdsa::Signature::from_slice(&sig).unwrap();
        let sig = sig.to_der().as_bytes().to_vec();

        vec![Signature { keyid, sig }]
    };

    let envelope = Envelope {
        payload_type,
        payload,
        signatures,
    };
    let envelope = envelope.into_json_string()?;

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
    let envelope = Envelope::try_from_json_string(envelope)?;

    if envelope.signatures.is_empty() {
        return Ok(false);
    }

    for signature in envelope.signatures.iter() {
        let did = did_key::PatchedKeyPair::try_from(signature.keyid.as_str()).expect("TODO");

        if let Err(_err) = did.verify(&envelope.payload, &signature.sig) {
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
        multihash::SHA2_256 => {
            digest.insert("sha256".to_owned(), hex::encode(cid.hash().digest()));
        }
        multihash::BLAKE3 => {
            digest.insert("blake3".to_owned(), hex::encode(cid.hash().digest()));
        }
        _ => {}
    }

    Ok(digest)
}
