use anyhow::{anyhow, Result};
use async_trait::async_trait;
use azure_storage::{prelude::*, ErrorKind};
use azure_storage_blobs::prelude::*;
use log::trace;

use crate::blob_store::{calc_and_validate_cid, BlobStore};

pub struct AzureBlob {
    account: String,
    key: String,
    container: String,

    client: Option<ClientBuilder>,
}

impl AzureBlob {
    pub fn new(account: String, key: String, container: String) -> Self {
        Self {
            account,
            key,
            container,
            client: None,
        }
    }
}

#[async_trait]
impl BlobStore for AzureBlob {
    async fn init(&mut self) -> Result<()> {
        let storage_credentials = StorageCredentials::access_key(&self.account, self.key.clone());

        let blob_client = ClientBuilder::new(&self.account, storage_credentials);

        self.client = blob_client.into();
        Ok(())
    }

    /// Check if a CID exists in the store
    async fn exists(&self, cid: &str) -> Result<bool> {
        let client = self.client.clone().ok_or(anyhow!("client not init"))?;

        let exists = client
            .blob_client(self.container.as_str(), cid)
            .exists()
            .await?;

        Ok(exists)
    }

    /// Get a blob from the store
    async fn get(&self, cid: &str) -> Result<Option<Vec<u8>>> {
        let client = self.client.clone().ok_or(anyhow!("client not init"))?;

        match client
            .blob_client(self.container.as_str(), cid)
            .get_content()
            .await
        {
            Ok(content) => Ok(Some(content)),
            Err(e) => {
                if let ErrorKind::HttpResponse { status, .. } = e.kind() {
                    if status.is_client_error() {
                        log::debug!("Client error downloading blob '{cid}'. (HTTP 4xx).");
                        return Ok(None);
                    }
                }
                Err(e.into())
            }
        }
    }

    /// Put a blob into the store
    async fn put(&self, blob: Vec<u8>, multicodec_code: u64, cid: Option<&str>) -> Result<String> {
        let cid = calc_and_validate_cid(&blob, multicodec_code, cid)?;

        trace!("put {cid}. blob size: {}", blob.len());
        let client = self.client.clone().ok_or(anyhow!("client not init"))?;

        client
            .blob_client(self.container.as_str(), &cid)
            .put_block_blob(blob)
            .content_type("text/plain")
            .await?;

        Ok(cid)
    }
}
