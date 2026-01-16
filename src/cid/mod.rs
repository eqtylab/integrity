pub mod blake3;
use std::str::FromStr;

use cid::Cid;

#[cfg(not(target_arch = "wasm32"))]
pub mod iroh;
pub mod jcs;

pub mod multicodec {
    pub const RAW_BINARY: u64 = 0x55;
    pub const BLAKE3_HASHSEQ: u64 = 0x80;
    pub const RDFC_1_0: u64 = 0xb403;
    pub const JSON_JCS: u64 = 0xb601;
}

pub mod multihash {
    pub const SHA2_256: u64 = 0x12;
    pub const BLAKE3: u64 = 0x1e;
}

use anyhow::Result;

pub fn strip_urn_cid(cid: &str) -> &str {
    if cid.starts_with("urn:cid:") {
        cid.strip_prefix("urn:cid:").unwrap()
    } else {
        cid
    }
}

pub fn strip_urn_uuid(uuid: &str) -> &str {
    if uuid.starts_with("urn:uuid:") {
        uuid.strip_prefix("urn:uuid:").unwrap()
    } else {
        uuid
    }
}

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

pub fn get_multicodec(cid: &str) -> Result<u64> {
    let cid = Cid::from_str(cid)?;
    Ok(cid.codec())
}
