//! Google Cloud Storage implementation of the [`BlobStore`] trait.
//!
//! This module provides a GCS-backed blob store that stores content-addressed
//! blobs in a Google Cloud Storage bucket.

use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use google_cloud_storage::client::Storage;
use log::{debug, trace};

use crate::blob_store::{calc_and_validate_cid, BlobStore};

/// A blob store implementation backed by Google Cloud Storage.
///
/// Blobs are stored in a specified bucket and folder, using their CID
/// (Content Identifier) as the object name.
pub struct GCS {
    /// The name of the GCS bucket.
    bucket: String,
    /// The folder prefix within the bucket (always ends with `/`).
    folder: String,
    /// The GCS client, initialized via [`GCS::init`].
    client: Option<Storage>,
}

impl GCS {
    /// Creates a new GCS blob store instance.
    ///
    /// # Arguments
    ///
    /// * `bucket` - The name of the GCS bucket to use.
    /// * `folder` - The folder prefix within the bucket. A trailing `/` will be
    ///   added if not present.
    ///
    /// # Returns
    ///
    /// A new [`GCS`] instance with an uninitialized client. Call [`BlobStore::init`]
    /// before using other methods.
    pub fn new(bucket: String, folder: String) -> Self {
        let folder = match folder.ends_with('/') {
            true => folder,
            false => format!("{folder}/"),
        };

        Self {
            bucket,
            folder,
            client: None,
        }
    }

    /// Returns the GCS bucket path in the format required by the API.
    fn bucket_path(&self) -> String {
        format!("projects/_/buckets/{}", self.bucket)
    }

    /// Constructs the full object name for a given CID.
    fn object_name(&self, cid: &str) -> String {
        format!("{folder}{cid}", folder = self.folder)
    }
}

#[async_trait]
impl BlobStore for GCS {
    /// Initializes the GCS client for this blob store.
    ///
    /// This must be called before any other operations. The client is built
    /// using default credentials from the environment.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Client initialized successfully.
    /// * `Err(_)` - Failed to build the GCS client.
    async fn init(&mut self) -> Result<()> {
        let client = Storage::builder().build().await?;
        self.client = Some(client);
        Ok(())
    }

    /// Checks if a blob with the given CID exists in the store.
    async fn exists(&self, cid: &str) -> Result<bool> {
        let client = self
            .client
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Client not initialized"))?;

        let object_name = self.object_name(cid);
        trace!("Checking existence of {}", object_name);

        match client
            .read_object(self.bucket_path(), &object_name)
            .send()
            .await
        {
            Ok(_) => Ok(true),
            Err(e) => {
                let err_str = format!("{e}");
                if err_str.contains("404") || err_str.contains("Not Found") {
                    Ok(false)
                } else {
                    Err(e.into())
                }
            }
        }
    }

    /// Retrieves a blob from the store by its CID.
    async fn get(&self, cid: &str) -> Result<Option<Vec<u8>>> {
        let client = self
            .client
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Client not initialized"))?;

        let object_name = self.object_name(cid);

        match client
            .read_object(self.bucket_path(), &object_name)
            .send()
            .await
        {
            Ok(mut reader) => {
                let mut bytes_vec = Vec::new();
                while let Some(data) = reader.next().await {
                    let data = data?;
                    bytes_vec.extend_from_slice(&data);
                }
                Ok(Some(bytes_vec))
            }
            Err(e) => {
                let err_str = format!("{e}");
                if err_str.contains("404") || err_str.contains("Not Found") {
                    debug!("Object not found in GCS: {}", object_name);
                    Ok(None)
                } else {
                    Err(e.into())
                }
            }
        }
    }

    /// Stores a blob in GCS.
    ///
    /// The blob is stored using its CID as the object name. If a CID is provided,
    /// it will be validated against the computed CID of the blob data.
    async fn put(&self, blob: Vec<u8>, multicodec_code: u64, cid: Option<&str>) -> Result<String> {
        let client = self
            .client
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Client not initialized"))?;

        let cid = calc_and_validate_cid(&blob, multicodec_code, cid)?;
        debug!("calculated cid: {}", cid);

        let object_name = self.object_name(&cid);

        let payload = Bytes::from(blob);
        client
            .write_object(self.bucket_path(), &object_name, payload)
            .send_unbuffered()
            .await?;

        trace!("Upload to GCS complete");
        Ok(cid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn put_gcs() {
        let mut gcs = GCS::new(String::from("ig-gcs-blob-store"), String::from("rootstore"));
        gcs.init().await.unwrap();
        let blob = "Hello World".to_string().into_bytes();
        let cid = gcs.put(blob, 0x55, None).await.unwrap();
        assert_eq!(
            cid,
            "bafkr4icb7a4uceploe5cefs4i3eqvohq7wjztsjafd6w2kejiszd75n7oy"
        );
    }

    #[tokio::test]
    async fn get_gcs() {
        let mut gcs = GCS::new(String::from("ig-gcs-blob-store"), String::from("rootstore"));
        gcs.init().await.unwrap();
        let bytes = gcs
            .get("bafkr4icb7a4uceploe5cefs4i3eqvohq7wjztsjafd6w2kejiszd75n7oy")
            .await
            .unwrap();
        assert!(bytes.is_some());
        assert_eq!(bytes.clone().unwrap().len(), 11);
        assert_eq!(bytes.unwrap(), "Hello World".to_string().into_bytes());
    }

    #[tokio::test]
    async fn exists_gcs() {
        let mut gcs = GCS::new(String::from("ig-gcs-blob-store"), String::from("rootstore"));
        gcs.init().await.unwrap();
        let exists = gcs
            .exists("bafkr4icb7a4uceploe5cefs4i3eqvohq7wjztsjafd6w2kejiszd75n7oy")
            .await
            .unwrap();
        assert!(exists);
    }
}
