#[cfg(any(
    feature = "blob-local",
    all(not(target_arch = "wasm32"), feature = "blob-azure"),
    all(not(target_arch = "wasm32"), feature = "blob-gcs"),
    all(not(target_arch = "wasm32"), feature = "blob-s3"),
))]
use anyhow::anyhow;
use anyhow::Result;
use async_trait::async_trait;
#[cfg(any(
    feature = "blob-local",
    all(not(target_arch = "wasm32"), feature = "blob-azure"),
    all(not(target_arch = "wasm32"), feature = "blob-gcs"),
    all(not(target_arch = "wasm32"), feature = "blob-s3"),
))]
use cid::{multihash::Multihash, Cid};

#[cfg(all(not(target_arch = "wasm32"), feature = "blob-azure"))]
pub mod azure_blob;
#[cfg(all(not(target_arch = "wasm32"), feature = "blob-gcs"))]
pub mod gcs;
#[cfg(feature = "blob-memory")]
pub mod in_memory;
#[cfg(feature = "blob-local")]
pub mod local_fs;
#[cfg(all(not(target_arch = "wasm32"), feature = "blob-s3"))]
pub mod s3;

#[cfg(all(not(target_arch = "wasm32"), feature = "blob-azure"))]
pub use azure_blob::AzureBlob;
#[cfg(all(not(target_arch = "wasm32"), feature = "blob-gcs"))]
pub use gcs::GCS;
#[cfg(feature = "blob-memory")]
pub use in_memory::InMemoryStore;
#[cfg(feature = "blob-local")]
pub use local_fs::LocalFs;
#[cfg(all(not(target_arch = "wasm32"), feature = "blob-s3"))]
pub use s3::S3;

#[cfg(any(
    feature = "blob-local",
    all(not(target_arch = "wasm32"), feature = "blob-azure"),
    all(not(target_arch = "wasm32"), feature = "blob-gcs"),
    all(not(target_arch = "wasm32"), feature = "blob-s3"),
))]
#[async_trait]
pub trait BlobStore {
    async fn init(&mut self) -> Result<()>;
    async fn exists(&self, cid: &str) -> Result<bool>;
    async fn get(&self, cid: &str) -> Result<Option<Vec<u8>>>;
    async fn put(&self, blob: Vec<u8>, multicodec_code: u64, cid: Option<&str>) -> Result<String>;
}

#[cfg(any(
    feature = "blob-local",
    all(not(target_arch = "wasm32"), feature = "blob-azure"),
    all(not(target_arch = "wasm32"), feature = "blob-gcs"),
    all(not(target_arch = "wasm32"), feature = "blob-s3"),
))]
pub(crate) fn calc_and_validate_cid(
    blob: &[u8],
    multicodec_code: u64,
    expected_cid: Option<&str>,
) -> Result<String> {
    let computed_cid = blake3_cid(multicodec_code, blob)?;

    if let Some(cid) = expected_cid {
        if cid != computed_cid {
            return Err(anyhow!(
                "Computed CID '{computed_cid}' doesn't match provided CID '{cid}'.",
            ));
        }
    }

    Ok(computed_cid)
}

#[cfg(any(
    feature = "blob-local",
    all(not(target_arch = "wasm32"), feature = "blob-azure"),
    all(not(target_arch = "wasm32"), feature = "blob-gcs"),
    all(not(target_arch = "wasm32"), feature = "blob-s3"),
))]
fn blake3_cid(codec: u64, data: &[u8]) -> Result<String> {
    #[cfg(not(target_arch = "wasm32"))]
    let hash = iroh_blake3::hash(data);

    #[cfg(target_arch = "wasm32")]
    let hash = blake3::hash(data);

    let multihash = Multihash::wrap(0x1e, hash.as_bytes())?;
    Ok(Cid::new_v1(codec, multihash).to_string())
}
