use std::{fs, path::PathBuf};

use anyhow::Result;
use async_trait::async_trait;
use log::{debug, trace};

use crate::blob_store::{calc_and_validate_cid, BlobStore};

pub struct LocalFs {
    path: PathBuf,
}

impl LocalFs {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

#[async_trait]
impl BlobStore for LocalFs {
    async fn init(&mut self) -> Result<()> {
        fs::create_dir_all(&self.path)?;
        Ok(())
    }

    async fn exists(&self, cid: &str) -> Result<bool> {
        trace!("check exists {cid}.");

        let path = self.path.join(cid);
        let exists = path.exists();

        Ok(exists)
    }

    async fn get(&self, cid: &str) -> Result<Option<Vec<u8>>> {
        trace!("get {cid}.");

        let path = self.path.join(cid);
        if path.exists() {
            let blob = fs::read(path)?;
            Ok(Some(blob))
        } else {
            Ok(None)
        }
    }

    async fn put(&self, blob: Vec<u8>, multicodec_code: u64, cid: Option<&str>) -> Result<String> {
        let cid = calc_and_validate_cid(&blob, multicodec_code, cid)?;

        trace!("put {cid}. blob size: {}", blob.len());

        let path = self.path.join(&cid);
        if path.exists() {
            debug!("blob with cid {cid} already exists.");
        } else {
            fs::write(path, &blob)?;
        }

        Ok(cid)
    }
}
