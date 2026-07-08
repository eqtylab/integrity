use std::collections::HashSet;

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
use cid::{multihash::MultihashGeneric, Cid};
use futures_util::{stream, StreamExt, TryStreamExt};

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
type Multihash = MultihashGeneric<64>;

const DEFAULT_BATCH_CONCURRENCY_LIMIT: usize = 16;

#[derive(Clone, Debug)]
pub struct BlobPut {
    pub blob: Vec<u8>,
    pub multicodec_code: u64,
    pub cid: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobPutResult {
    pub cid: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobGetResult {
    pub cid: String,
    pub blob: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobExistsResult {
    pub cid: String,
    pub exists: bool,
}

#[async_trait]
pub trait BlobStore {
    async fn init(&mut self) -> Result<()>;
    async fn exists(&self, cid: &str) -> Result<bool>;
    async fn get(&self, cid: &str) -> Result<Option<Vec<u8>>>;
    async fn put(&self, blob: Vec<u8>, multicodec_code: u64, cid: Option<&str>) -> Result<String>;

    fn batch_concurrency_limit(&self) -> usize {
        DEFAULT_BATCH_CONCURRENCY_LIMIT
    }

    async fn exists_many(&self, cids: Vec<String>) -> Result<Vec<BlobExistsResult>> {
        let concurrency_limit = self.batch_concurrency_limit().max(1);
        let mut results = stream::iter(cids.into_iter().enumerate())
            .map(|(index, cid)| async move {
                let exists = self.exists(&cid).await?;
                Ok::<_, anyhow::Error>((index, BlobExistsResult { cid, exists }))
            })
            .buffer_unordered(concurrency_limit)
            .try_collect::<Vec<_>>()
            .await?;

        results.sort_by_key(|(index, _)| *index);
        Ok(results.into_iter().map(|(_, result)| result).collect())
    }

    async fn get_many(&self, cids: Vec<String>) -> Result<Vec<BlobGetResult>> {
        let mut seen = HashSet::new();

        // Remove common non-CID strings & duplicates
        let cids = cids
            .into_iter()
            .filter(|cid| !cid.starts_with("urn:uuid:") && !cid.starts_with("did:key:"))
            .filter(|cid| seen.insert(cid.clone()))
            .collect::<Vec<_>>();

        let concurrency_limit = self.batch_concurrency_limit().max(1);
        let mut results = stream::iter(cids.into_iter().enumerate())
            .map(|(index, cid)| async move {
                let blob = self.get(&cid).await?;
                Ok::<_, anyhow::Error>((index, BlobGetResult { cid, blob }))
            })
            .buffer_unordered(concurrency_limit)
            .try_collect::<Vec<_>>()
            .await?;

        results.sort_by_key(|(index, _)| *index);
        Ok(results.into_iter().map(|(_, result)| result).collect())
    }

    async fn put_many(&self, blobs: Vec<BlobPut>) -> Result<Vec<BlobPutResult>> {
        let concurrency_limit = self.batch_concurrency_limit().max(1);
        let mut results = stream::iter(blobs.into_iter().enumerate())
            .map(|(index, blob)| async move {
                let BlobPut {
                    blob,
                    multicodec_code,
                    cid,
                } = blob;
                let cid = self.put(blob, multicodec_code, cid.as_deref()).await?;
                Ok::<_, anyhow::Error>((index, BlobPutResult { cid }))
            })
            .buffer_unordered(concurrency_limit)
            .try_collect::<Vec<_>>()
            .await?;

        results.sort_by_key(|(index, _)| *index);
        Ok(results.into_iter().map(|(_, result)| result).collect())
    }
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

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Mutex};

    use super::*;

    #[derive(Default)]
    struct TestBlobStore {
        blobs: Mutex<HashMap<String, Vec<u8>>>,
    }

    #[async_trait::async_trait]
    impl BlobStore for TestBlobStore {
        async fn init(&mut self) -> Result<()> {
            Ok(())
        }

        async fn exists(&self, cid: &str) -> Result<bool> {
            Ok(self.blobs.lock().unwrap().contains_key(cid))
        }

        async fn get(&self, cid: &str) -> Result<Option<Vec<u8>>> {
            Ok(self.blobs.lock().unwrap().get(cid).cloned())
        }

        async fn put(
            &self,
            blob: Vec<u8>,
            _multicodec_code: u64,
            cid: Option<&str>,
        ) -> Result<String> {
            let mut blobs = self.blobs.lock().unwrap();
            let cid = cid
                .map(str::to_owned)
                .unwrap_or_else(|| format!("cid-{}", blobs.len()));
            blobs.insert(cid.clone(), blob);
            Ok(cid)
        }
    }

    #[test]
    fn default_batch_methods_preserve_input_order() {
        futures_executor::block_on(async {
            let store = TestBlobStore::default();

            let put_results = store
                .put_many(vec![
                    BlobPut {
                        blob: b"one".to_vec(),
                        multicodec_code: 0x55,
                        cid: Some("cid-one".to_owned()),
                    },
                    BlobPut {
                        blob: b"two".to_vec(),
                        multicodec_code: 0x55,
                        cid: Some("cid-two".to_owned()),
                    },
                ])
                .await
                .unwrap();

            assert_eq!(
                put_results,
                vec![
                    BlobPutResult {
                        cid: "cid-one".to_owned()
                    },
                    BlobPutResult {
                        cid: "cid-two".to_owned()
                    },
                ]
            );

            let get_results = store
                .get_many(vec![
                    "cid-two".to_owned(),
                    "missing".to_owned(),
                    "cid-one".to_owned(),
                ])
                .await
                .unwrap();
            assert_eq!(
                get_results,
                vec![
                    BlobGetResult {
                        cid: "cid-two".to_owned(),
                        blob: Some(b"two".to_vec())
                    },
                    BlobGetResult {
                        cid: "missing".to_owned(),
                        blob: None
                    },
                    BlobGetResult {
                        cid: "cid-one".to_owned(),
                        blob: Some(b"one".to_vec())
                    },
                ]
            );

            let exists_results = store
                .exists_many(vec![
                    "missing".to_owned(),
                    "cid-one".to_owned(),
                    "cid-two".to_owned(),
                ])
                .await
                .unwrap();
            assert_eq!(
                exists_results,
                vec![
                    BlobExistsResult {
                        cid: "missing".to_owned(),
                        exists: false
                    },
                    BlobExistsResult {
                        cid: "cid-one".to_owned(),
                        exists: true
                    },
                    BlobExistsResult {
                        cid: "cid-two".to_owned(),
                        exists: true
                    },
                ]
            );
        });
    }
}
