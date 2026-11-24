use std::{fs, path::Path};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use did_key::Document;
use log::info;
use reqwest::header::HeaderMap;
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
    /// HTTP client for requests to the auth service. `None` uses a default client.
    /// Not serialized.
    #[serde(skip)]
    pub client: Option<reqwest::Client>,
    /// Headers added to every request to the auth service, such as a request ID or
    /// W3C trace context. Not serialized.
    #[serde(skip)]
    pub headers: HeaderMap,
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
        Self::create_with(api_key, url, None, HeaderMap::new()).await
    }

    /// Creates a new Auth Service signer like [`Self::create`], sending the DID document
    /// request and every later signing request through `client` with `headers` added.
    ///
    /// # Arguments
    ///
    /// * `api_key` - API key for authenticating with the auth service.
    /// * `url` - Base URL of the auth service endpoint.
    /// * `client` - HTTP client to use. `None` uses a default client.
    /// * `headers` - Headers added to every request, such as correlation headers.
    ///
    /// # Returns
    ///
    /// A new `AuthServiceSigner` instance with the DID document from the service.
    pub async fn create_with(
        api_key: String,
        url: String,
        client: Option<reqwest::Client>,
        headers: HeaderMap,
    ) -> Result<Self> {
        log::info!("Creating AuthServiceSigner from {url}");
        let response = client
            .clone()
            .unwrap_or_default()
            .get(format!("{url}/api/v1/protected/did-doc"))
            .headers(headers.clone())
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
            client,
            headers,
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

        let request = self
            .client
            .clone()
            .unwrap_or_default()
            .post(format!("{url}/api/v1/protected/sign"))
            .headers(self.headers.clone())
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

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use did_key::{DIDCore, Ed25519KeyPair, Generate};
    use reqwest::header::{HeaderMap, HeaderValue};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    use super::AuthServiceSigner;
    use crate::signer::Signer;

    /// Serves the DID document and a signature, recording each request's head
    async fn serve(requests: Arc<Mutex<Vec<String>>>) -> String {
        let did_doc = Ed25519KeyPair::new().get_did_document(did_key::Config {
            use_jose_format: true,
            serialize_secrets: false,
        });
        let did_doc = serde_json::to_string(&did_doc).unwrap();
        let signature = format!("{{\"signature\":\"{}\"}}", "ab".repeat(64));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut buf = vec![0; 16 * 1024];
                let n = stream.read(&mut buf).await.unwrap();
                let head = String::from_utf8_lossy(&buf[..n]).to_lowercase();
                let body = if head.starts_with("get /api/v1/protected/did-doc") {
                    did_doc.clone()
                } else {
                    signature.clone()
                };
                requests.lock().unwrap().push(head);
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn create_with_sends_headers_on_every_request() {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let url = serve(requests.clone()).await;
        let mut headers = HeaderMap::new();
        headers.insert("x-request-id", HeaderValue::from_static("req-123"));

        let signer = AuthServiceSigner::create_with(
            "key".to_owned(),
            url,
            Some(reqwest::Client::new()),
            headers,
        )
        .await
        .unwrap();
        signer.sign(b"data").await.unwrap();

        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        for head in requests.iter() {
            assert!(
                head.contains("x-request-id: req-123"),
                "missing header in {head}"
            );
            assert!(
                head.contains("authorization: bearer key"),
                "missing auth in {head}"
            );
        }
    }

    #[test]
    fn client_and_headers_are_not_serialized() {
        let mut headers = HeaderMap::new();
        headers.insert("x-request-id", HeaderValue::from_static("req-123"));
        let signer = AuthServiceSigner {
            api_key: "key".to_owned(),
            url: "http://auth".to_owned(),
            did_doc: Ed25519KeyPair::new().get_did_document(did_key::Config {
                use_jose_format: true,
                serialize_secrets: false,
            }),
            client: Some(reqwest::Client::new()),
            headers,
        };

        let json = serde_json::to_string(&signer).unwrap();
        assert!(!json.contains("req-123"));
        let loaded: AuthServiceSigner = serde_json::from_str(&json).unwrap();
        assert!(loaded.client.is_none());
        assert!(loaded.headers.is_empty());
    }
}
