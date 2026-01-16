use anyhow::{anyhow, Result};
use async_trait::async_trait;

use crate::cid::blake3::blake3_cid;

pub mod azure_blob;
pub mod in_memory;
pub mod local_fs;
pub mod s3;

pub use azure_blob::AzureBlob;
pub use in_memory::InMemoryStore;
pub use local_fs::LocalFs;
pub use s3::S3;

#[async_trait]
pub trait BlobStore {
    /// Initialize the store
    async fn init(&mut self) -> Result<()>;

    /// Check if a CID exists in the store
    async fn exists(&self, cid: &str) -> Result<bool>;

    /// Get a blob from the store
    async fn get(&self, cid: &str) -> Result<Option<Vec<u8>>>;

    /// Put a blob into the store
    /// If cid is provided, it will be compared to the computed cid. If they don't match, an error will be returned.
    async fn put(&self, blob: Vec<u8>, multicodec_code: u64, cid: Option<&str>) -> Result<String>;
}

/// Calculates the blake cid of the blob.
/// If expected_cid is provided, it will be compared to the computed cid.
/// Returns OK(computed_cid) if the computed cid matches the expected cid.
fn calc_and_validate_cid(
    blob: &[u8],
    multicodec_code: u64,
    expected_cid: Option<&str>,
) -> Result<String> {
    let computed_cid = blake3_cid(multicodec_code, blob)?;

    // validate CID if one was provided
    if let Some(cid) = expected_cid {
        if cid != computed_cid {
            return Err(anyhow!(
                "Computed CID '{computed_cid}' doesn't match provided CID '{cid}'.",
            ));
        }
    }
    Ok(computed_cid)
}
