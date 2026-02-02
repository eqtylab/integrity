use anyhow::Result;
use async_trait::async_trait;
use aws_config::meta::region::RegionProviderChain;
use aws_sdk_s3::{config::Region, types::Object, Client};
use log::{debug, trace};

use crate::blob_store::{calc_and_validate_cid, BlobStore};

/// AWS S3 blob storage backend
///
/// Stores blobs in an S3 bucket under a specified folder prefix.
pub struct S3 {
    region: String,
    bucket: String,
    folder: String,
    client: Option<Client>,
}

impl S3 {
    /// Creates a new S3 blob store
    ///
    /// # Arguments
    /// * `region` - AWS region (e.g., "us-east-1")
    /// * `bucket` - S3 bucket name
    /// * `folder` - Folder prefix within the bucket
    pub fn new(region: String, bucket: String, folder: String) -> Self {
        let folder = match folder.ends_with('/') {
            true => folder,
            false => format!("{folder:}/"),
        };

        Self {
            region,
            bucket,
            folder,
            client: None,
        }
    }
}

#[async_trait]
impl BlobStore for S3 {
    async fn init(&mut self) -> Result<()> {
        let region_provider = RegionProviderChain::first_try(Region::new(self.region.clone()));

        let config = aws_config::from_env().region(region_provider).load().await;

        self.client = Some(Client::new(&config));
        Ok(())
    }

    /// Check if a CID exists in the store
    async fn exists(&self, cid: &str) -> Result<bool> {
        let client = self
            .client
            .clone()
            .ok_or_else(|| anyhow::anyhow!("Client not initialized"))?;

        let mut response = client
            .list_objects_v2()
            .bucket(self.bucket.to_owned())
            .prefix(self.folder.to_owned())
            .max_keys(50)
            .into_paginator()
            .send();

        trace!("Searching for {}", cid);
        while let Some(result) = response.next().await {
            match result {
                Ok(output) => {
                    for object in output.contents() {
                        if search_objects(object, cid, &self.folder) {
                            return Ok(true);
                        }
                    }
                }
                Err(err) => {
                    println!("{err:?}");
                    return Err(anyhow::anyhow!("Error listing objects"));
                }
            }
        }

        Ok(false)
    }

    /// Get a blob from the store
    async fn get(&self, cid: &str) -> Result<Option<Vec<u8>>> {
        let client = match self.client.clone() {
            Some(client) => client,
            None => {
                return Err(anyhow::anyhow!("Client not initialized"));
            }
        };

        let object = client
            .get_object()
            .bucket(&self.bucket)
            .key(format!("{folder:}{cid:}", folder = self.folder))
            .send()
            .await;

        match object {
            Ok(mut object) => {
                let mut bytes_vec = Vec::new();
                println!("Downloading data");
                while let Some(bytes) = object.body.try_next().await? {
                    bytes_vec.extend_from_slice(&bytes);
                }

                Ok(Some(bytes_vec))
            }
            Err(e) => {
                println!("Error: {:?}", e);
                Ok(None)
            }
        }
    }

    /// Put a blob into the store
    async fn put(&self, blob: Vec<u8>, multicodec_code: u64, cid: Option<&str>) -> Result<String> {
        let client = match self.client.clone() {
            Some(client) => client,
            None => {
                return Err(anyhow::anyhow!("Client not initialized"));
            }
        };

        let cid = calc_and_validate_cid(&blob, multicodec_code, cid)?;
        debug!("caclulated cid: {}", cid);

        client
            .put_object()
            .bucket(self.bucket.to_owned())
            .key(format!("{folder:}{cid:}", folder = self.folder))
            .body(blob.into())
            .send()
            .await?;

        trace!("Upload complete");
        Ok(cid)
    }
}

fn search_objects(object: &Object, cid: &str, folder: &str) -> bool {
    trace!(" - {}", object.key().unwrap_or("Unknown"));
    match object.key() {
        Some(key) => {
            let key = key.strip_prefix(folder).unwrap_or("");
            key == cid
        }
        None => false,
    }
}

#[cfg(test)]
#[cfg(feature = "s3")]
mod tests {
    use super::*;

    #[tokio::test]
    async fn put_s3() {
        let mut s3 = S3::new(
            String::from("us-west-1"),
            String::from("ig-s3-blob-store"),
            String::from("rootstore"),
        );
        s3.init().await.unwrap();
        let blob = "Hello World".to_string().into_bytes();
        let bytes = s3.put(blob, 0x55, None).await.unwrap();
        assert_eq!(
            bytes,
            "bafkr4icb7a4uceploe5cefs4i3eqvohq7wjztsjafd6w2kejiszd75n7oy"
        );
    }

    #[tokio::test]
    async fn get_s3() {
        let mut s3 = S3::new(
            String::from("us-west-1"),
            String::from("ig-s3-blob-store"),
            String::from("rootstore"),
        );
        s3.init().await.unwrap();
        let bytes = s3
            .get("bafkr4icb7a4uceploe5cefs4i3eqvohq7wjztsjafd6w2kejiszd75n7oy")
            .await
            .unwrap();
        assert_eq!(bytes.is_some(), true);
        assert_eq!(bytes.clone().unwrap().len(), 11);
        assert_eq!(bytes.unwrap(), "Hello World".to_string().into_bytes());
    }

    #[tokio::test]
    async fn exists_s3() {
        let mut s3 = S3::new(
            String::from("us-west-1"),
            String::from("ig-s3-blob-store"),
            String::from("rootstore"),
        );
        s3.init().await.unwrap();
        let exists = s3
            .exists("bafkr4icxlhpyx57vldjntdc7q7rckwmw3e2b5uxnmd5bqkvwomtl3jbpzq")
            .await
            .unwrap();
        assert_eq!(exists, true);
    }
}
