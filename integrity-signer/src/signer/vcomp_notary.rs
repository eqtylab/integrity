use std::{
    collections::HashMap,
    fs,
    path::PathBuf,
    sync::{
        atomic::{AtomicU8, Ordering},
        Arc, OnceLock,
    },
    time::Duration,
};

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use base64::engine::{general_purpose::STANDARD as BASE64, Engine};
use did_key::{DIDCore, Document, Generate, P256KeyPair};
use log::debug;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::signer::{
    p256_jwk::{fix_p256_jwk_from_encoded_point, p256_encoded_point_from_public_key},
    Signer,
};

/// Signer implementation for verified computing notary services.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VCompNotarySigner {
    /// Protocol version
    pub version: String,
    /// URL of the notary service endpoint
    pub url: String,
    /// DID document from the notary service
    pub did_doc: Document,
    /// DID of the entity operating the notary
    pub operated_by: Option<String>,
    /// DID of the execution environment
    pub executed_on: Option<String>,
    /// DID registration statements from the notary
    pub credentials: Option<HashMap<String, serde_json::Value>>,
    /// Binary blobs associated with DID registration
    pub did_blobs: Option<HashMap<String, Vec<u8>>>,
    /// Extra headers generated per request, so a caller can vary them per call.
    /// A plain `fn` pointer keeps `Clone`/`Debug` derives; serde skips it.
    #[serde(default, skip)]
    pub extra_headers: ExtraHeaders,
    /// How requests reach the notary. Shared by clones, so a signer and its
    /// copies keep using one connection.
    #[serde(default, skip)]
    pub connection: NotaryConnection,
}

/// Response header a notary sends when a caller it attributed on a connection
/// stays attributed for the rest of that connection.
pub const CONNECTION_ATTRIBUTION_HEADER: &str = "x-argus-connection-attribution";

const MODE_UNKNOWN: u8 = 0;
const MODE_REUSE: u8 = 1;
const MODE_PER_REQUEST: u8 = 2;

/// Below the notary's default idle limit (120s), so the client never reuses a
/// connection the notary is about to close.
const KEEP_ALIVE_IDLE: Duration = Duration::from_secs(90);

/// The connection(s) a [`VCompNotarySigner`] sends its requests over.
///
/// A notary that announces [`CONNECTION_ATTRIBUTION_HEADER`] attributes the
/// caller once per connection, so every request goes over one kept-alive
/// connection. Any other notary attributes each request on its own, so against
/// those this keeps one connection per request, closed after its response.
#[derive(Clone, Debug, Default)]
pub struct NotaryConnection {
    clients: Arc<OnceLock<Clients>>,
    mode: Arc<AtomicU8>,
}

#[derive(Debug)]
struct Clients {
    /// Keeps one idle connection to the notary.
    keep: reqwest::Client,
    /// Never reuses a connection.
    per_request: reqwest::Client,
}

impl NotaryConnection {
    fn clients(&self) -> Result<&Clients> {
        if let Some(clients) = self.clients.get() {
            return Ok(clients);
        }
        // Redirects must not silently replay the same extra headers elsewhere.
        let keep = reqwest::Client::builder()
            .pool_max_idle_per_host(1)
            .pool_idle_timeout(KEEP_ALIVE_IDLE)
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        let per_request = reqwest::Client::builder()
            .pool_max_idle_per_host(0)
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        // A concurrent first use may have won; either pair is equivalent.
        let _ = self.clients.set(Clients { keep, per_request });
        Ok(self.clients.get().expect("set above"))
    }

    /// Whether the notary has announced per-connection attribution.
    pub fn reuses_connection(&self) -> bool {
        self.mode.load(Ordering::Relaxed) == MODE_REUSE
    }

    /// Kept-alive client until the first response says the notary attributes
    /// per request; either kind attributes a connection's first request alike.
    fn request(&self, method: reqwest::Method, url: &str) -> Result<reqwest::RequestBuilder> {
        let clients = self.clients()?;
        Ok(if self.mode.load(Ordering::Relaxed) == MODE_PER_REQUEST {
            clients
                .per_request
                .request(method, url)
                .header(reqwest::header::CONNECTION, "close")
        } else {
            clients.keep.request(method, url)
        })
    }

    /// Learn the notary's mode from its first response.
    fn observe(&self, response: &reqwest::Response) {
        let announced = response
            .headers()
            .get(CONNECTION_ATTRIBUTION_HEADER)
            .is_some_and(|value| value == "per-connection");
        let mode = if announced {
            MODE_REUSE
        } else {
            MODE_PER_REQUEST
        };
        let _ =
            self.mode
                .compare_exchange(MODE_UNKNOWN, mode, Ordering::Relaxed, Ordering::Relaxed);
    }

    /// Rebuilds the request per retry so the extra-headers generator runs
    /// again. A 403 is retried: it gives the notary longer to observe the socket.
    async fn send(
        &self,
        method: reqwest::Method,
        url: &str,
        extra_headers: ExtraHeaders,
        build: impl Fn(reqwest::RequestBuilder) -> reqwest::RequestBuilder,
    ) -> Result<reqwest::Response> {
        for retry in 0..=MAX_FORBIDDEN_RETRIES {
            let request = build(with_extra_headers(
                self.request(method.clone(), url)?,
                extra_headers,
            ));
            let response = request.send().await?;
            self.observe(&response);
            if response.status() == reqwest::StatusCode::FORBIDDEN && retry < MAX_FORBIDDEN_RETRIES
            {
                // Read the refusal fully, so the connection can carry the retry.
                let _ = response.bytes().await;
                retry_delay(retry).await;
                continue;
            }
            return Ok(response);
        }
        unreachable!("bounded retry loop always returns on its final attempt")
    }
}

/// Per-request extra headers for [`VCompNotarySigner`]. `None` adds nothing.
pub type ExtraHeaders = Option<fn() -> Vec<(String, String)>>;

/// Retry a refused attribution at most three times after the initial attempt.
const MAX_FORBIDDEN_RETRIES: usize = 3;

#[derive(Debug)]
struct NotaryHttpError {
    status: reqwest::StatusCode,
    body: String,
}

impl std::fmt::Display for NotaryHttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "VComp Notary returned {} for /v1/sign: {}",
            self.status, self.body
        )
    }
}

impl std::error::Error for NotaryHttpError {}

async fn retry_delay(retry: usize) {
    tokio::time::sleep(std::time::Duration::from_millis(250 * (retry as u64 + 1))).await;
}

/// GET `url` over `connection`, retrying a refusal; any other error status is
/// an error.
async fn get_with_extra_headers(
    connection: &NotaryConnection,
    url: &str,
    extra_headers: ExtraHeaders,
) -> Result<reqwest::Response> {
    let response = connection
        .send(reqwest::Method::GET, url, extra_headers, |request| request)
        .await?;
    Ok(response.error_for_status()?)
}

/// Apply freshly generated extra headers to a reqwest builder.
fn with_extra_headers(
    mut builder: reqwest::RequestBuilder,
    extra_headers: ExtraHeaders,
) -> reqwest::RequestBuilder {
    if let Some(generate) = extra_headers {
        for (name, value) in generate() {
            builder = builder.header(name, value);
        }
    }
    builder
}

fn strip_urn_cid(cid: &str) -> &str {
    cid.strip_prefix("urn:cid:").unwrap_or(cid)
}

impl VCompNotarySigner {
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

    /// Creates a new VCompNotarySigner by connecting to a verified computing notary service.
    ///
    /// # Arguments
    ///
    /// * `url` - URL of the notary service endpoint.
    /// * `pub_key` - Optional hex-encoded public key; if not provided, fetches from the service.
    ///
    /// # Returns
    ///
    /// A new `VCompNotarySigner` with the DID document and registration data from the service.
    pub async fn create(url: &str, pub_key: Option<String>) -> Result<Self> {
        Self::create_with_headers(url, pub_key, None).await
    }

    /// As [`Self::create`], attaching `extra_headers` to every request the
    /// resulting signer makes, including the three made here.
    pub async fn create_with_headers(
        url: &str,
        pub_key: Option<String>,
        extra_headers: ExtraHeaders,
    ) -> Result<Self> {
        Self::create_with_connection(url, pub_key, extra_headers, NotaryConnection::default()).await
    }

    /// As [`Self::create_with_headers`], sending every request over
    /// `connection`; an earlier signer's connection keeps its attributed socket.
    pub async fn create_with_connection(
        url: &str,
        pub_key: Option<String>,
        extra_headers: ExtraHeaders,
        connection: NotaryConnection,
    ) -> Result<Self> {
        let client = &connection;

        let pub_key = if let Some(pub_key) = pub_key {
            pub_key
        } else {
            get_with_extra_headers(client, &format!("{url}/v1/public_key"), extra_headers)
                .await?
                .json::<Value>()
                .await?
                .get("public_key")
                .ok_or_else(|| anyhow!("API response is missing `public_key` field"))?
                .as_str()
                .ok_or_else(|| anyhow!("API response `public_key` field is not a string"))?
                .to_owned()
        };
        let pub_key = hex::decode(pub_key)?;

        log::trace!("Importing a secp256r1 VComp Notary signer");
        let did_doc = Self::did_doc_from_public_key(&pub_key)?;

        let response = get_with_extra_headers(client, &format!("{url}/get_dids"), extra_headers)
            .await?
            .json::<Value>()
            .await?;

        let operated_by = response
            .get("operatedBy")
            .and_then(|v| v.as_str())
            .map(String::from);

        let executed_on = response
            .get("executedOn")
            .and_then(|v| v.as_str())
            .map(String::from);

        let manifest =
            get_with_extra_headers(client, &format!("{url}/v1/did_registration"), extra_headers)
                .await?
                .json::<Value>()
                .await?;

        let signer = VCompNotarySigner {
            url: url.to_owned(),
            version: "1".to_owned(),
            did_doc,
            operated_by,
            executed_on,
            credentials: manifest["statements"].as_object().map(|obj| {
                obj.iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect::<HashMap<String, serde_json::Value>>()
            }),

            extra_headers,

            did_blobs: manifest["blobs"]
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
                .transpose()?,

            connection,
        };

        Ok(signer)
    }

    /// Exercise the kept-alive connection so the notary does not close it as
    /// idle. Does nothing, and returns `false`, unless the notary attributes
    /// per connection.
    pub async fn keep_alive(&self) -> Result<bool> {
        if !self.connection.reuses_connection() {
            return Ok(false);
        }
        get_with_extra_headers(
            &self.connection,
            &format!("{}/v1/public_key", self.url),
            self.extra_headers,
        )
        .await?
        .bytes()
        .await?;
        Ok(true)
    }

    /// Copies the signer's DID statements and blobs to the specified directories.
    ///
    /// # Arguments
    ///
    /// * `statement_dir` - Directory to write DID statement JSON-LD files.
    /// * `blob_dir` - Directory to write binary blob files.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or an error if writing fails.
    pub fn copy_data(&self, statement_dir: PathBuf, blob_dir: PathBuf) -> Result<()> {
        if let Some(statements) = self.credentials.clone() {
            fs::create_dir_all(&statement_dir).ok();
            for (cid, content) in statements {
                let cid = strip_urn_cid(&cid);
                let path = statement_dir.join(format!("{}.jsonld", cid));
                fs::write(&path, serde_json::to_vec(&content)?)?;
                log::debug!("Wrote VComp DID statement to: {:?}", path);
            }
        }

        if let Some(blobs) = self.did_blobs.clone() {
            fs::create_dir_all(&blob_dir).ok();
            for (cid, content) in blobs {
                let path = blob_dir.join(&cid);
                fs::write(&path, content)?;
                log::debug!("Wrote VComp DID blob to: {:?}", path);
            }
        }
        Ok(())
    }
}

#[async_trait]
impl Signer for VCompNotarySigner {
    async fn sign(&self, data: &[u8]) -> Result<[u8; 64]> {
        // Refusals are retried inside `NotaryConnection::send`.
        self.sign_once(data).await
    }

    async fn get_did_doc(&self) -> Result<Option<Document>> {
        Ok(Some(self.did_doc.clone()))
    }
}

impl VCompNotarySigner {
    async fn sign_once(&self, data: &[u8]) -> Result<[u8; 64]> {
        let payload = json!({ "data": hex::encode(data) }).to_string();
        let url = format!("{}/v1/sign", self.url);
        debug!("POST {url}");
        let res = self
            .connection
            .send(reqwest::Method::POST, &url, self.extra_headers, |request| {
                request
                    .header(reqwest::header::ACCEPT, "application/json")
                    .header(reqwest::header::CONTENT_TYPE, "application/json")
                    .body(payload.clone())
            })
            .await?;

        let status = res.status();
        let bytes = res.bytes().await?;

        // A refusal to sign is a runtime condition, an error rather than a panic.
        if !status.is_success() {
            return Err(NotaryHttpError {
                status,
                body: String::from_utf8_lossy(&bytes).into_owned(),
            }
            .into());
        }

        let v: Value = serde_json::from_slice(&bytes).with_context(|| {
            format!(
                "VComp Notary /v1/sign response is not JSON: {}",
                String::from_utf8_lossy(&bytes)
            )
        })?;

        let sig_hex = v
            .get("signature")
            .and_then(|s| s.as_str())
            .ok_or_else(|| anyhow!("VComp Notary /v1/sign response has no `signature` field"))?;
        let sig = hex::decode(sig_hex)
            .with_context(|| "VComp Notary `signature` field is not hex".to_owned())?;
        let sig_len = sig.len();
        let sig: [u8; 64] = sig.try_into().map_err(|_| {
            anyhow!("VComp Notary signature must be 64 bytes (r||s), got {sig_len}")
        })?;

        Ok(sig)
    }
}

#[cfg(test)]
mod tests {
    use base64::engine::{general_purpose::URL_SAFE_NO_PAD as BASE64_URL_NO_PAD, Engine};
    use did_key::KeyFormat;
    use p256::ecdsa::SigningKey;

    use super::*;

    #[test]
    fn compressed_vcomp_public_key_repairs_verification_method_jwk() {
        let signing_key = SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
        let verifying_key = signing_key.verifying_key();
        let compressed_pub_key = verifying_key.to_encoded_point(true);
        let uncompressed_pub_key = verifying_key.to_encoded_point(false);

        let key_pair = P256KeyPair::from_public_key(compressed_pub_key.as_bytes());
        let broken_did_doc = key_pair.get_did_document(did_key::Config {
            use_jose_format: true,
            serialize_secrets: true,
        });

        let fixed_did_doc =
            VCompNotarySigner::did_doc_from_public_key(compressed_pub_key.as_bytes()).unwrap();

        let expected_x = BASE64_URL_NO_PAD.encode(uncompressed_pub_key.x().unwrap());
        let expected_y = BASE64_URL_NO_PAD.encode(uncompressed_pub_key.y().unwrap());
        let compressed_b64 = BASE64_URL_NO_PAD.encode(compressed_pub_key.as_bytes());

        let broken_jwk = match &broken_did_doc.verification_method[0].public_key {
            Some(KeyFormat::JWK(jwk)) => jwk,
            _ => panic!("expected JWK verification method"),
        };
        assert_eq!(broken_jwk.x.as_deref(), Some(compressed_b64.as_str()));
        assert_eq!(broken_jwk.y, None);

        let fixed_jwk = match &fixed_did_doc.verification_method[0].public_key {
            Some(KeyFormat::JWK(jwk)) => jwk,
            _ => panic!("expected JWK verification method"),
        };
        assert_eq!(fixed_jwk.x.as_deref(), Some(expected_x.as_str()));
        assert_eq!(fixed_jwk.y.as_deref(), Some(expected_y.as_str()));
    }
}

#[cfg(test)]
mod connection_tests {
    use super::*;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    fn headers() -> Vec<(String, String)> {
        vec![("x-padding".to_string(), "x".repeat(1500))]
    }

    /// Requests a stand-in notary served: (connection number, request line).
    type Served = Arc<std::sync::Mutex<Vec<(usize, String)>>>;

    /// A stand-in notary that answers every request on whichever connection it
    /// arrives on, honouring keep-alive, and announces per-connection
    /// attribution when `announce` is set.
    async fn stand_in_notary(announce: bool) -> (String, Served) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let served: Served = Default::default();
        let signing_key = p256::ecdsa::SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
        let pub_key = hex::encode(
            signing_key
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes(),
        );
        let log = served.clone();
        tokio::spawn(async move {
            for connection in 0.. {
                let (socket, _) = listener.accept().await.unwrap();
                tokio::spawn(serve_connection(
                    socket,
                    connection,
                    announce,
                    log.clone(),
                    pub_key.clone(),
                ));
            }
        });
        (url, served)
    }

    async fn serve_connection(
        mut socket: tokio::net::TcpStream,
        connection: usize,
        announce: bool,
        log: Served,
        pub_key: String,
    ) {
        let mut buf = Vec::new();
        loop {
            let head_end = loop {
                if let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    break at + 4;
                }
                let mut chunk = [0u8; 4096];
                match socket.read(&mut chunk).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                }
            };
            let head = String::from_utf8_lossy(&buf[..head_end]).to_lowercase();
            let body_len: usize = head
                .lines()
                .find_map(|line| line.strip_prefix("content-length:"))
                .map_or(0, |len| len.trim().parse().unwrap());
            while buf.len() < head_end + body_len {
                let mut chunk = [0u8; 4096];
                match socket.read(&mut chunk).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                }
            }
            buf.drain(..head_end + body_len);
            let line = head.lines().next().unwrap().to_owned();
            let close = head.contains("connection: close");
            log.lock().unwrap().push((connection, line.clone()));

            let body = if line.contains("/v1/public_key") {
                json!({ "public_key": pub_key })
            } else if line.contains("/v1/did_registration") {
                json!({ "statements": {}, "blobs": {} })
            } else if line.contains("/v1/sign") {
                json!({ "signature": "00".repeat(64) })
            } else {
                json!({})
            }
            .to_string();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{}{}\r\n{body}",
                body.len(),
                if announce {
                    "x-argus-connection-attribution: per-connection\r\n"
                } else {
                    ""
                },
                if close { "Connection: close\r\n" } else { "" },
            );
            if socket.write_all(response.as_bytes()).await.is_err() || close {
                return;
            }
        }
    }

    /// A notary that attributes per connection gets the whole exchange, from
    /// registration through signing and keep-alive, on the one socket it
    /// attributed.
    #[tokio::test]
    async fn reuses_one_connection_when_the_notary_announces_it() {
        let (url, served) = stand_in_notary(true).await;
        let signer = VCompNotarySigner::create_with_connection(
            &url,
            None,
            Some(headers),
            NotaryConnection::default(),
        )
        .await
        .unwrap();
        signer.sign(b"payload").await.unwrap();
        assert!(signer.keep_alive().await.unwrap());
        // A second signer on the same connection, as in a settle retry.
        let again = VCompNotarySigner::create_with_connection(
            &url,
            None,
            Some(headers),
            signer.connection.clone(),
        )
        .await
        .unwrap();
        again.sign(b"payload").await.unwrap();

        let served = served.lock().unwrap();
        assert_eq!(served.len(), 9, "{served:?}");
        assert!(
            served.iter().all(|(connection, _)| *connection == 0),
            "expected one connection, got {served:?}"
        );
    }

    /// A notary that does not announce it keeps the original behaviour: one
    /// connection per request, and nothing kept alive.
    #[tokio::test]
    async fn one_connection_per_request_when_the_notary_does_not_announce_it() {
        let (url, served) = stand_in_notary(false).await;
        let signer = VCompNotarySigner::create_with_connection(
            &url,
            None,
            Some(headers),
            NotaryConnection::default(),
        )
        .await
        .unwrap();
        signer.sign(b"payload").await.unwrap();
        assert!(!signer.keep_alive().await.unwrap());

        let served = served.lock().unwrap();
        let connections: std::collections::HashSet<_> =
            served.iter().map(|(connection, _)| *connection).collect();
        assert_eq!(served.len(), 4, "{served:?}");
        assert_eq!(
            connections.len(),
            served.len(),
            "expected a connection per request, got {served:?}"
        );
    }

    #[tokio::test]
    async fn sign_sends_extra_headers_on_the_wire() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 16384];
            let n = socket.read(&mut buf).await.unwrap();
            let request = String::from_utf8_lossy(&buf[..n]).to_string();
            let body = br#"{"signature":"00"}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                body.len()
            );
            socket.write_all(response.as_bytes()).await.unwrap();
            socket.write_all(body).await.unwrap();
            socket.flush().await.unwrap();
            request
        });

        let signer = VCompNotarySigner {
            version: "1".to_owned(),
            url: format!("http://{addr}"),
            // A minimal document: sign() never reads it.
            did_doc: did_key::Document {
                context: String::new(),
                id: "did:key:test".to_string(),
                key_agreement: None,
                authentication: None,
                assertion_method: None,
                capability_delegation: None,
                capability_invocation: None,
                verification_method: vec![],
            },
            operated_by: None,
            executed_on: None,
            credentials: None,
            did_blobs: None,
            extra_headers: Some(headers),
            connection: NotaryConnection::default(),
        };
        // The stub returns a 1-byte signature, so signing errors on length,
        // which is irrelevant here: the request has already been sent.
        let _ = signer.sign(b"payload").await;

        let request = server.await.unwrap();
        let lower = request.to_lowercase();
        assert!(
            lower.contains("x-padding:"),
            "sign() did not send the padding header:\n{}",
            &request[..request.len().min(400)]
        );
        assert!(
            request.len() > 1400,
            "padded request was only {} bytes",
            request.len()
        );
    }
}
