use std::collections::HashMap;

use anyhow::Result;
use async_trait::async_trait;

use crate::blob_store::BlobStore;

/// In-memory blob storage for testing
///
/// Stores blobs in a HashMap. Not persistent. Used for testing and development.
#[cfg(not(target_arch = "wasm32"))]
pub struct InMemoryStore {
    /// Map of CIDs to blob data
    pub blobs: HashMap<String, Vec<u8>>,
}

#[async_trait]
#[cfg(not(target_arch = "wasm32"))]
impl BlobStore for InMemoryStore {
    async fn init(&mut self) -> Result<()> {
        Ok(())
    }

    async fn exists(&self, cid: &str) -> Result<bool> {
        log::trace!("check exists {cid}.");

        let exists = self.blobs.contains_key(cid);

        Ok(exists)
    }

    async fn get(&self, cid: &str) -> Result<Option<Vec<u8>>> {
        log::trace!("get {cid}.");

        let blob = self.blobs.get(cid).map(ToOwned::to_owned);

        Ok(blob)
    }

    async fn put(
        &self,
        _blob: Vec<u8>,
        _multicodec_code: u64,
        _cid: Option<&str>,
    ) -> Result<String> {
        unimplemented!();
    }
}
