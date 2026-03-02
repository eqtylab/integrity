use std::{fs, path::Path};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use did_key::Document;
use log::info;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::signer::Signer;

/// Signer implementation that delegates signing to a remote auth service.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthServiceSigner {
    /// API key for authenticating with the service
    pub api_key: String,
    /// URL of the auth service endpoint
    pub url: String,
    /// DID document retrieved from the auth service
    pub did_doc: Document,
}

impl AuthServiceSigner {
    /// Creates a new Auth Service signer by connecting to the platform and retrieving the DID key.
    ///
    /// # Arguments
    ///
    /// * `api_key` - API key for authenticating with the auth service.
    /// * `url` - Base URL of the auth service endpoint.
    ///
    /// # Returns
    ///
    /// A new `AuthServiceSigner` instance with the DID document from the service.
    pub async fn create(api_key: String, url: String) -> Result<Self> {
        log::info!("Creating AuthServiceSigner from {url}");
        let response = reqwest::Client::new()
            .get(format!("{url}/api/v1/protected/did-doc"))
            .bearer_auth(&api_key)
            .send()
            .await?;

        let status = response.status();
        let text = response.text().await?;

        log::trace!("Response status: {status}, body: {text}");

        if !status.is_success() {
            return Err(anyhow!("Request failed with status {status}: {text}"));
        }

        if text.is_empty() {
            return Err(anyhow!("Server returned empty response"));
        }

        let response: Value = serde_json::from_str(&text)
            .map_err(|e| anyhow!("Failed to parse JSON response: {e}. Response body: {text}"))?;

        let did_doc = serde_json::from_value::<Document>(response)
            .map_err(|e| anyhow!("Failed to deserialize DID document: {e}"))?;

        log::debug!("DID Doc {:?}", did_doc);

        Ok(AuthServiceSigner {
            api_key,
            url,
            did_doc,
        })
    }

    /// Loads an Auth Service signer from a configuration file.
    ///
    /// # Arguments
    ///
    /// * `signer_info_file` - Path to the JSON configuration file.
    ///
    /// # Returns
    ///
    /// `Some(AuthServiceSigner)` if the file exists and is valid, `None` if the file doesn't exist.
    pub fn load(signer_info_file: &Path) -> Result<Option<Self>> {
        if signer_info_file.exists() {
            let contents = fs::read_to_string(signer_info_file)?;
            let signer = serde_json::from_str::<AuthServiceSigner>(&contents)?;

            Ok(Some(signer))
        } else {
            info!("No auth service signer info found");

            Ok(None)
        }
    }
}

#[derive(serde::Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
struct SignRequest {
    data_hash: String,
}

#[async_trait]
impl Signer for AuthServiceSigner {
    async fn sign(&self, data: &[u8]) -> Result<[u8; 64]> {
        let url = &self.url;

        // Hash the data with SHA-256 and hex-encode it
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hasher.finalize();
        let hash_hex = hex::encode(hash);

        let request = SignRequest {
            data_hash: hash_hex,
        };

        let request = reqwest::Client::new()
            .post(format!("{url}/api/v1/protected/sign"))
            .bearer_auth(self.api_key.clone())
            .json(&request);

        log::trace!("Sign request '{:?}'", request);

        let response = request.send().await?;

        let status = response.status();
        let text = response.text().await?;

        log::debug!("Response status: {status}, body: {text}");

        if !status.is_success() {
            return Err(anyhow!("Request failed with status {status}: {text}"));
        }

        if text.is_empty() {
            return Err(anyhow!("Server returned empty response"));
        }

        let response: Value = serde_json::from_str(&text)
            .map_err(|e| anyhow!("Failed to parse JSON response: {e}. Response body: {text}"))?;

        log::info!("Gov Studio Signer sign response: {response:?}");
        let sig_hex = response
            .get("signature")
            .ok_or_else(|| anyhow!("API response is missing 'signature' field"))?
            .as_str()
            .ok_or_else(|| anyhow!("API response 'signature' field is not a string"))?;

        let sig = hex::decode(sig_hex)?;
        let sig = sig
            .clone()
            .try_into()
            .map_err(|_| anyhow!("Signature is not 64 bytes: length = {}", sig.len()))?;

        Ok(sig)
    }

    async fn get_did_doc(&self) -> Result<Option<Document>> {
        Ok(Some(self.did_doc.clone()))
    }
}
