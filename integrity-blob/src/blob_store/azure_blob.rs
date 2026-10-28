use anyhow::{anyhow, Result};
use async_trait::async_trait;
use log::{debug, trace, warn};
use object_store::{
    azure::{MicrosoftAzure, MicrosoftAzureBuilder},
    path::Path,
    Attribute, Attributes, ClientOptions, Error, ObjectStore, ObjectStoreExt,
};

use crate::blob_store::{calc_and_validate_cid, BlobStore};

/// Azure Blob Storage implementation of BlobStore
///
/// Stores blobs in Azure Blob Storage containers, indexed by CID.
pub struct AzureBlob {
    account: String,
    key: String,
    container: String,

    client: Option<MicrosoftAzure>,
}

impl AzureBlob {
    /// Creates a new Azure Blob Storage client
    ///
    /// # Arguments
    /// * `account` - Azure storage account name
    /// * `key` - Azure storage account key
    /// * `container` - Container name to store blobs in
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
        // object_store limits a whole request to 30s by default, which a large blob
        // can exceed. Keep its connect timeout and retries, but not that limit.
        let client_options = ClientOptions::new().with_timeout_disabled();

        let client = MicrosoftAzureBuilder::new()
            .with_account(&self.account)
            .with_access_key(&self.key)
            .with_container_name(&self.container)
            .with_client_options(client_options)
            .build()?;

        self.client = Some(client);
        Ok(())
    }

    /// Check if a CID exists in the store
    async fn exists(&self, cid: &str) -> Result<bool> {
        let client = self.client.as_ref().ok_or(anyhow!("client not init"))?;

        match client.head(&Path::from(cid)).await {
            Ok(_) => Ok(true),
            Err(Error::NotFound { .. }) => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    /// Get a blob from the store
    async fn get(&self, cid: &str) -> Result<Option<Vec<u8>>> {
        let client = self
            .client
            .as_ref()
            .ok_or(anyhow!("client not initialized"))?;

        let location = Path::from(cid);
        let content = async { client.get(&location).await?.bytes().await };

        match content.await {
            Ok(content) => Ok(Some(content.to_vec())),
            Err(Error::NotFound { .. }) => {
                debug!("Blob '{cid}' not found in Azure Blob Storage. status=404");
                Ok(None)
            }
            Err(e) => {
                warn!("Azure Blob Storage returned an error downloading blob '{cid}'. error={e}");
                Err(e.into())
            }
        }
    }

    /// Put a blob into the store
    async fn put(&self, blob: Vec<u8>, multicodec_code: u64, cid: Option<&str>) -> Result<String> {
        let cid = calc_and_validate_cid(&blob, multicodec_code, cid)?;

        trace!("put {cid}. blob size: {}", blob.len());
        let client = self.client.as_ref().ok_or(anyhow!("client not init"))?;

        let mut attributes = Attributes::new();
        attributes.insert(Attribute::ContentType, "text/plain".into());

        client
            .put_opts(&Path::from(cid.as_str()), blob.into(), attributes.into())
            .await?;

        Ok(cid)
    }
}
