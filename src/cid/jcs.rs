use anyhow::Result;
use serde::Serialize;

use crate::cid::{blake3::blake3_cid, multicodec, prepend_urn_cid};

/// Canonicalizes the [`serde_json::Value`] to JCS and calculates the blake3 cid
/// Returns the cid string and the bytes of the JCS canonicalization
pub fn compute_jcs_cid(json: &serde_json::Value) -> Result<(String, Vec<u8>)> {
    let jcs_json = serde_jcs::to_string(json)?;

    let jcs_cid = blake3_cid(multicodec::JSON_JCS, jcs_json.as_bytes())?;

    Ok((jcs_cid, jcs_json.as_bytes().to_vec()))
}

/// Serializes, then Canonicalizes the [`obj`] to JCS and calculates the blake3 cid
/// Returns the cid string (with 'urn:cid:') and the bytes of the JCS canonicalization
pub fn compute_jcs_cid_with_prefix<T: Serialize>(obj: &T) -> Result<(String, Vec<u8>)> {
    let value = serde_json::to_value(obj)?;
    let (cid, bytes) = compute_jcs_cid(&value)?;
    let cid = prepend_urn_cid(&cid)?;
    Ok((cid, bytes))
}
