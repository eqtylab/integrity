use std::{
    collections::HashMap,
    fs,
    os::fd::AsRawFd,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use base64::engine::{general_purpose::STANDARD as BASE64, Engine};
use did_key::{DIDCore, Document, Generate, P256KeyPair};
use log::trace;
use p256::ecdsa::Signature;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::signer::{
    p256_jwk::{fix_p256_jwk_from_encoded_point, p256_encoded_point_from_public_key},
    Signer,
};

const DEVICE_PATH: &str = "/dev/eqty-notary";
const DEFAULT_MANIFEST_PATH: &str = "/var/lib/eqty-notary/tee-manifest.jsonld";

const IOC_READ: u32 = 2;
const IOC_WRITE: u32 = 1;
const MAGIC: u32 = b'E' as u32;
const MAX_DATA_LEN: usize = 4096;
const MAX_SIG_LEN: usize = 72;
const PUBKEY_SIZE: usize = 73;
const SIGN_REQ_SIZE: usize = 4 + MAX_DATA_LEN + 4 + MAX_SIG_LEN;

fn ioc(direction: u32, nr: u32, size: u32) -> u64 {
    ((direction as u64) << 30) | (((size & 0x3FFF) as u64) << 16) | ((MAGIC as u64) << 8) | nr as u64
}

const IOCTL_GET_PUBKEY: u64 = ((IOC_READ as u64) << 30) | ((PUBKEY_SIZE as u64) << 16) | ((MAGIC as u64) << 8) | 1;
const IOCTL_SIGN: u64 =
    (((IOC_READ | IOC_WRITE) as u64) << 30) | ((SIGN_REQ_SIZE as u64) << 16) | ((MAGIC as u64) << 8) | 2;

fn strip_urn_cid(cid: &str) -> &str {
    cid.strip_prefix("urn:cid:").unwrap_or(cid)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VCompNotaryModSigner {
    pub version: String,
    pub device_path: String,
    pub manifest_path: Option<String>,
    pub did_doc: Document,
    pub operated_by: Option<String>,
    pub executed_on: Option<String>,
    pub did_statements: Option<HashMap<String, serde_json::Value>>,
    pub did_blobs: Option<HashMap<String, Vec<u8>>>,
}

impl VCompNotaryModSigner {
    fn did_doc_from_public_key(pub_key: &[u8]) -> Result<Document> {
        let key_pair = P256KeyPair::from_public_key(pub_key);
        let mut did_doc = key_pair.get_did_document(did_key::Config {
            use_jose_format: true,
            serialize_secrets: true,
        });
        let encoded_point = p256_encoded_point_from_public_key(pub_key)?;
        fix_p256_jwk_from_encoded_point(&mut did_doc, &encoded_point, None)?;

        Ok(did_doc)
    }

    fn load_manifest(
        manifest_path: Option<&str>,
    ) -> Result<(
        Option<HashMap<String, serde_json::Value>>,
        Option<HashMap<String, Vec<u8>>>,
        Option<String>,
    )> {
        let manifest_path = manifest_path.unwrap_or(DEFAULT_MANIFEST_PATH);
        let path = Path::new(manifest_path);

        if !path.exists() {
            return Ok((None, None, None));
        }

        let manifest = fs::read_to_string(path)?;
        let manifest: Value = serde_json::from_str(&manifest)?;

        let did_statements = manifest["statements"].as_object().map(|obj| {
            obj.iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect::<HashMap<String, serde_json::Value>>()
        });

        let did_blobs = manifest["blobs"]
            .as_object()
            .map(|obj| {
                obj.iter()
                    .map(|(k, v)| {
                        let inner = v.as_str().unwrap_or("").trim_matches('"');
                        let decoded = BASE64.decode(inner)?;
                        Ok((k.clone(), decoded))
                    })
                    .collect::<Result<_>>()
            })
            .transpose()?;

        Ok((did_statements, did_blobs, Some(manifest_path.to_string())))
    }

    fn get_pubkey_raw(device_path: &str) -> Result<Vec<u8>> {
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(device_path)?;

        let mut buf = [0u8; PUBKEY_SIZE];
        let rc = unsafe { libc::ioctl(file.as_raw_fd(), IOCTL_GET_PUBKEY, buf.as_mut_ptr()) };
        if rc < 0 {
            return Err(std::io::Error::last_os_error().into());
        }

        let len = u32::from_le_bytes(buf[4..8].try_into().unwrap()) as usize;
        if len == 0 || len > 65 {
            return Err(anyhow!("invalid public key length returned from device: {len}"));
        }

        Ok(buf[8..8 + len].to_vec())
    }

    pub fn create(
        device_path: Option<String>,
        manifest_path: Option<String>,
        operated_by: Option<String>,
        executed_on: Option<String>,
    ) -> Result<Self> {
        let device_path = device_path.unwrap_or_else(|| DEVICE_PATH.to_string());
        let pub_key = Self::get_pubkey_raw(&device_path)?;
        let did_doc = Self::did_doc_from_public_key(&pub_key)?;

        let (did_statements, did_blobs, manifest_path) =
            Self::load_manifest(manifest_path.as_deref())?;

        let default_did = did_doc.id.clone();

        Ok(Self {
            version: "1".to_string(),
            device_path,
            manifest_path,
            did_doc,
            operated_by: operated_by.or_else(|| Some(default_did.clone())),
            executed_on: executed_on.or(Some(default_did)),
            did_statements,
            did_blobs,
        })
    }

    pub fn copy_data(&self, statement_dir: PathBuf, blob_dir: PathBuf) -> Result<()> {
        if let Some(statements) = self.did_statements.clone() {
            fs::create_dir_all(&statement_dir).ok();
            for (cid, content) in statements {
                let cid = strip_urn_cid(&cid);
                let path = statement_dir.join(format!("{}.jsonld", cid));
                fs::write(&path, serde_json::to_vec(&content)?)?;
                trace!("Wrote EQTY device DID statement to: {:?}", path);
            }
        }

        if let Some(blobs) = self.did_blobs.clone() {
            fs::create_dir_all(&blob_dir).ok();
            for (cid, content) in blobs {
                let path = blob_dir.join(&cid);
                fs::write(&path, content)?;
                trace!("Wrote EQTY device DID blob to: {:?}", path);
            }
        }

        Ok(())
    }
}

#[async_trait]
impl Signer for VCompNotaryModSigner {
    async fn sign(&self, data: &[u8]) -> Result<[u8; 64]> {
        if data.is_empty() {
            return Err(anyhow!("data to sign must not be empty"));
        }
        if data.len() > MAX_DATA_LEN {
            return Err(anyhow!(
                "data too large for eqty-notary device: {} bytes (max {})",
                data.len(),
                MAX_DATA_LEN
            ));
        }

        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.device_path)?;

        let mut req = [0u8; SIGN_REQ_SIZE];
        req[0..4].copy_from_slice(&(data.len() as u32).to_le_bytes());
        req[4..4 + data.len()].copy_from_slice(data);

        let rc = unsafe { libc::ioctl(file.as_raw_fd(), IOCTL_SIGN, req.as_mut_ptr()) };
        if rc < 0 {
            return Err(std::io::Error::last_os_error().into());
        }

        let sig_len_offset = 4 + MAX_DATA_LEN;
        let sig_len =
            u32::from_le_bytes(req[sig_len_offset..sig_len_offset + 4].try_into().unwrap()) as usize;
        if sig_len == 0 || sig_len > MAX_SIG_LEN {
            return Err(anyhow!("invalid signature length returned from device: {sig_len}"));
        }

        let sig_offset = sig_len_offset + 4;
        let der_sig = &req[sig_offset..sig_offset + sig_len];
        let signature = Signature::from_der(der_sig)?;

        Ok(signature.to_bytes().into())
    }

    async fn get_did_doc(&self) -> Result<Option<Document>> {
        Ok(Some(self.did_doc.clone()))
    }
}
