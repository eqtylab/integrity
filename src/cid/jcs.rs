use anyhow::Result;
use serde::Serialize;

use crate::cid::{blake3::blake3_cid, multicodec, prepend_urn_cid};

/// Canonicalizes a JSON value to JCS and calculates the blake3 CID.
///
/// # Arguments
///
/// * `json` - The JSON value to canonicalize and hash.
///
/// # Returns
///
/// A tuple containing the CID string and the bytes of the JCS canonicalization.
pub fn compute_jcs_cid(json: &serde_json::Value) -> Result<(String, Vec<u8>)> {
    let jcs_json = serde_jcs::to_string(json)?;

    let jcs_cid = blake3_cid(multicodec::JSON_JCS, jcs_json.as_bytes())?;

    Ok((jcs_cid, jcs_json.as_bytes().to_vec()))
}

/// Serializes and canonicalizes an object to JCS, then calculates the blake3 CID.
///
/// # Arguments
///
/// * `obj` - The serializable object to canonicalize and hash.
///
/// # Returns
///
/// A tuple containing the CID string (with `urn:cid:` prefix) and the bytes of the JCS canonicalization.
pub fn compute_jcs_cid_with_prefix<T: Serialize>(obj: &T) -> Result<(String, Vec<u8>)> {
    let value = serde_json::to_value(obj)?;
    let (cid, bytes) = compute_jcs_cid(&value)?;
    let cid = prepend_urn_cid(&cid)?;
    Ok((cid, bytes))
}
