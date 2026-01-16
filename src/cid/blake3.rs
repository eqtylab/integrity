use anyhow::Result;
use cid::{multihash::MultihashGeneric, Cid};

use crate::cid::multicodec;
type Multihash = MultihashGeneric<64>;

pub fn cid(codec: u64, multihash: Multihash) -> String {
    Cid::new_v1(codec, multihash).to_string()
}

pub fn cid_from_blake3_hash(codec: u64, hash: &[u8]) -> Result<String> {
    let multihash = Multihash::wrap(0x1e, hash)?;

    Ok(cid(codec, multihash))
}

pub fn blake3_cid(codec: u64, data: &[u8]) -> Result<String> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        // using iroh_blake3 here instead of the blake3 hashing baked into the cid
        // crate, this is to avoid the issue of multiple version of the blake3
        // c library being included in downstream builds that depend on iroh and
        // causing duplicate errors at link time
        let hash = iroh_blake3::hash(data);
        let multihash = Multihash::wrap(0x1e, hash.as_bytes())?;
        Ok(cid(codec, multihash))
    }

    #[cfg(target_arch = "wasm32")]
    {
        // On wasm, use the regular blake3 crate since there are no C library linking concerns
        let hash = blake3::hash(data);
        let multihash = Multihash::wrap(0x1e, hash.as_bytes())?;
        Ok(cid(codec, multihash))
    }
}

pub fn blake3_cid_raw_binary(data: &[u8]) -> Result<String> {
    blake3_cid(multicodec::RAW_BINARY, data)
}
