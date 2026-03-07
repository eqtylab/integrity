/// JSON-LD context loading utilities.
pub mod loader;
/// N-Quads parsing and canonicalization utilities.
pub mod nquads;
/// JSON-LD to N-Quads conversion.
pub mod to_nquads;

use anyhow::Result;
use cid::{multihash::MultihashGeneric, Cid};
use serde_json::Value;

use crate::{nquads::canonicalize_nquads, to_nquads::jsonld_to_nquads};

type Multihash = MultihashGeneric<64>;

const MULTICODEC_RDFC_1_0: u64 = 0xb403;

/// Returns the Integrity Graph common context link as a CID URN.
///
/// # Returns
/// URN string in format `urn:cid:{cid}` for the IG common context.
pub fn ig_common_context_link() -> String {
    let cid: &'static str = "bafkr4ic7ydwk3rtoltyzx4zn3vvu3r7hpzxtmbzmnksotx7k5nbnwclf6m";

    format!("urn:cid:{cid}").trim_end().to_owned()
}

/// Computes RDFC CID for JSON-LD data.
///
/// Converts JSON-LD to N-Quads, canonicalizes using URDNA2015, and computes a CID.
///
/// # Arguments
/// * `jsonld` - JSON-LD document as a serde_json::Value.
///
/// # Returns
/// Tuple of (CID string, canonicalized N-Quads bytes).
pub async fn compute_rdfc_cid_for_jsonld(jsonld: Value) -> Result<(String, Vec<u8>)> {
    let nquads = jsonld_to_nquads(jsonld, None).await?;

    let canon_nquads = canonicalize_nquads(nquads)?;

    let cid = blake3_cid(MULTICODEC_RDFC_1_0, canon_nquads.as_bytes())?;

    Ok((cid, canon_nquads.as_bytes().to_vec()))
}

/// Converts JSON-LD to canonical N-Quads format.
///
/// # Arguments
/// * `jsonld` - JSON-LD document as a serde_json::Value.
///
/// # Returns
/// Canonicalized N-Quads string.
pub async fn canon_nquads_from_jsonld(jsonld: Value) -> Result<String> {
    let nquads = jsonld_to_nquads(jsonld, None).await?;

    canonicalize_nquads(nquads)
}

fn blake3_cid(codec: u64, data: &[u8]) -> Result<String> {
    #[cfg(not(target_arch = "wasm32"))]
    let hash = iroh_blake3::hash(data);

    #[cfg(target_arch = "wasm32")]
    let hash = blake3::hash(data);

    let multihash = Multihash::wrap(0x1e, hash.as_bytes())?;
    Ok(Cid::new_v1(codec, multihash).to_string())
}
