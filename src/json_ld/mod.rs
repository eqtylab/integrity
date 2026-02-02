/// JSON-LD context loading utilities
pub mod loader;
/// JSON-LD to N-Quads conversion
pub mod to_nquads;

use anyhow::Result;
use serde_json::Value;

use crate::{
    cid::{blake3::blake3_cid, multicodec},
    json_ld::to_nquads::jsonld_to_nquads,
    nquads::canonicalize_nquads,
};

/// Returns the Integrity Graph common context link as a CID URN
///
/// # Returns
/// URN string in format `urn:cid:{cid}` for the IG common context
pub fn ig_common_context_link() -> String {
    let cid: &'static str = "bafkr4ibtc72t26blsnipjniwpoawtopufixoe7bbloqk7ko65cizgnhgnq";

    format!("urn:cid:{cid}").trim_end().to_owned()
}

/// Computes RDFC CID for JSON-LD data
///
/// Converts JSON-LD to N-Quads, canonicalizes using URDNA2015, and computes a CID.
///
/// # Arguments
/// * `jsonld` - JSON-LD document as a serde_json::Value
///
/// # Returns
/// Tuple of (CID string, canonicalized N-Quads bytes)
pub async fn compute_rdfc_cid_for_jsonld(jsonld: Value) -> Result<(String, Vec<u8>)> {
    let nquads = jsonld_to_nquads(jsonld, None).await?;

    let canon_nquads = canonicalize_nquads(nquads)?;

    let cid = blake3_cid(multicodec::RDFC_1_0, canon_nquads.as_bytes())?;

    Ok((cid, canon_nquads.as_bytes().to_vec()))
}

/// Converts JSON-LD to canonical N-Quads format
///
/// # Arguments
/// * `jsonld` - JSON-LD document as a serde_json::Value
///
/// # Returns
/// Canonicalized N-Quads string
pub async fn canon_nquads_from_jsonld(jsonld: Value) -> Result<String> {
    let nquads = jsonld_to_nquads(jsonld, None).await?;

    let canon_nquads = canonicalize_nquads(nquads)?;

    Ok(canon_nquads)
}
