/// JSON-LD context loading utilities.
pub mod loader;
/// N-Quads parsing and canonicalization utilities.
pub mod nquads;
/// JSON-LD to N-Quads conversion.
pub mod to_nquads;

use anyhow::Result;
use cid::{multihash::Multihash as MultihashGeneric, Cid};
use serde_json::Value;

use crate::{nquads::canonicalize_nquads, to_nquads::jsonld_to_nquads};

type Multihash = MultihashGeneric<64>;

const MULTICODEC_RDFC_1_0: u64 = 0xb403;

/// Returns the Integrity Graph common context link as a CID URN.
///
/// # Returns
/// URN string in format `urn:cid:{cid}` for the IG common context.
pub fn ig_common_context_link() -> String {
    let cid: &'static str = "bafkr4icploa577ziqnb57jlpoj7l2hi5kgt3knxpdtunlttjd3q33zeqpy";

    format!("urn:cid:{cid}").trim_end().to_owned()
}

/// Returns the computation context link as a CID URN.
///
/// This context extends the IG common context with the `startTime`, `endTime`,
/// `span` and `parentSpan` terms of a `ComputationRegistration`. Statements that
/// use none of those terms keep the common context, so their CIDs are unchanged.
///
/// # Returns
/// URN string in format `urn:cid:{cid}` for the computation context.
pub fn ig_computation_context_link() -> String {
    let cid: &'static str = "bafkr4iduavib2lgjcmx5n4ydefbbc62ngyannzi566zv5fsozgbwwfw27u";

    format!("urn:cid:{cid}")
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
