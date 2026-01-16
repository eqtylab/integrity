/// BLAKE3-based CID utilities
pub mod blake3;
use std::str::FromStr;

use cid::Cid;

/// Iroh-specific CID operations
#[cfg(not(target_arch = "wasm32"))]
pub mod iroh;
/// JSON Canonicalization Scheme (JCS) CID operations
pub mod jcs;

/// Multicodec identifiers for content types
pub mod multicodec {
    /// Raw binary data
    pub const RAW_BINARY: u64 = 0x55;
    /// BLAKE3 hash sequence
    pub const BLAKE3_HASHSEQ: u64 = 0x80;
    /// RDF Dataset Canonicalization (RDFC) 1.0
    pub const RDFC_1_0: u64 = 0xb403;
    /// JSON Canonicalization Scheme (JCS)
    pub const JSON_JCS: u64 = 0xb601;
}

/// Multihash identifiers for hash algorithms
pub mod multihash {
    /// SHA2-256 hash
    pub const SHA2_256: u64 = 0x12;
    /// BLAKE3 hash
    pub const BLAKE3: u64 = 0x1e;
}

use anyhow::Result;

/// Strips the 'urn:cid:' prefix from a CID string if present
///
/// # Arguments
/// * `cid` - The CID string, optionally with 'urn:cid:' prefix
///
/// # Returns
/// The CID without the prefix
pub fn strip_urn_cid(cid: &str) -> &str {
    if cid.starts_with("urn:cid:") {
        cid.strip_prefix("urn:cid:").unwrap()
    } else {
        cid
    }
}

/// Strips the 'urn:uuid:' prefix from a UUID string if present
///
/// # Arguments
/// * `uuid` - The UUID string, optionally with 'urn:uuid:' prefix
///
/// # Returns
/// The UUID without the prefix
pub fn strip_urn_uuid(uuid: &str) -> &str {
    if uuid.starts_with("urn:uuid:") {
        uuid.strip_prefix("urn:uuid:").unwrap()
    } else {
        uuid
    }
}

/// Prepends 'urn:cid:' to a CID string if not already present
///
/// # Arguments
/// * `cid` - The CID string
///
/// # Returns
/// The CID with 'urn:cid:' prefix
///
/// # Panics
/// Panics if the CID string is empty
pub fn prepend_urn_cid(cid: &str) -> Result<String> {
    assert!(
        !cid.is_empty(),
        "attempted to prepend 'urn:cid' to an empty string"
    );

    if cid.starts_with("urn:cid:") {
        Ok(cid.to_string())
    } else {
        Ok(format!("urn:cid:{}", cid))
    }
}

/// Prepends 'urn:uuid:' to a UUID string if not already present
///
/// # Arguments
/// * `uuid` - The UUID string
///
/// # Returns
/// The UUID with 'urn:uuid:' prefix
///
/// # Panics
/// Panics if the UUID string is empty
pub fn prepend_urn_uuid(uuid: &str) -> Result<String> {
    assert!(
        !uuid.is_empty(),
        "attempted to prepend 'urn:uuid' to an empty string"
    );

    if uuid.starts_with("urn:uuid:") {
        Ok(uuid.to_string())
    } else {
        Ok(format!("urn:uuid:{}", uuid))
    }
}

/// Extracts the multicodec identifier from a CID string
///
/// # Arguments
/// * `cid` - The CID string
///
/// # Returns
/// The multicodec identifier
pub fn get_multicodec(cid: &str) -> Result<u64> {
    let cid = Cid::from_str(cid)?;
    Ok(cid.codec())
}
