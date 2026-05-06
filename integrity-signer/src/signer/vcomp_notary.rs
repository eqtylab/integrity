use std::{collections::HashMap, fs, path::PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use base64::engine::{general_purpose::STANDARD as BASE64, Engine};
use did_key::{DIDCore, Document, Generate, P256KeyPair};
use http_body_util::{BodyExt, Full};
use hyper::{body::Bytes, Method, Request, StatusCode};
use hyper_util::rt::TokioIo;
use log::debug;
use p256::EncodedPoint;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::net::TcpStream;

#[cfg(unix)]
use tokio::net::UnixStream;

use crate::signer::{
    p256_jwk::{fix_p256_jwk_from_encoded_point, p256_encoded_point_from_public_key},
    Signer,
};

const DEFAULT_UNIX_AUTHORITY: &str = "x";
const REGISTRATIONS_PATH: &str = "/v1/registrations";
const SIGN_PATH: &str = "/v1/sign";
const SIGN_HASH_ALG: &str = "SHA256";
const SIGN_ALGO: &str = "ECDSA";

/// Signer implementation for verified computing notary services.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VCompNotarySigner {
    /// Protocol version.
    pub version: String,
    /// Notary service endpoint. Use an HTTP URL for TCP dev mode, `unix:///path/to.sock`,
    /// or a plain absolute Unix socket path such as `/var/run/eqty-notary/eqty-notary.sock`.
    pub url: String,
    /// DID document derived from the notary registration public key.
    pub did_doc: Document,
    /// DID of the entity operating the notary.
    pub operated_by: Option<String>,
    /// DID of the execution environment.
    pub executed_on: Option<String>,
    /// DID registration statements from older notary APIs.
    pub did_statements: Option<HashMap<String, serde_json::Value>>,
    /// Binary blobs associated with older DID registration APIs.
    pub did_blobs: Option<HashMap<String, Vec<u8>>>,
    /// SEC1-compressed P-256 public key returned by the notary, lower-case hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    /// BLAKE3 binary hash associated with the notary registration, lower-case hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binary_hash: Option<String>,
    /// Binary path used to create the notary registration, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binary_path: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RegistrationResponse {
    binary_hash: String,
    binary_path: Option<String>,
    did: String,
    public_key: String,
}

#[derive(Debug, Deserialize)]
struct SignResponse {
    signature: String,
    public_key: String,
    did: String,
    binary_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum NotaryEndpoint {
    Unix {
        socket_path: PathBuf,
        authority: String,
    },
    Tcp {
        address: String,
        authority: String,
        base_path: String,
    },
}

fn strip_urn_cid(cid: &str) -> &str {
    cid.strip_prefix("urn:cid:").unwrap_or(cid)
}

impl VCompNotarySigner {
    fn did_doc_from_public_key(pub_key: &[u8]) -> Result<Document> {
        let key_pair = P256KeyPair::from_public_key(pub_key);
        let mut did_doc = key_pair.get_did_document(did_key::Config {
            use_jose_format: true,
            serialize_secrets: false,
        });
        let encoded_point = p256_encoded_point_from_public_key(pub_key)?;
        fix_p256_jwk_from_encoded_point(&mut did_doc, &encoded_point, None)?;

        Ok(did_doc)
    }

    fn from_public_key(
        url: &str,
        public_key: &str,
        expected_did: Option<&str>,
        binary_hash: Option<String>,
        binary_path: Option<String>,
    ) -> Result<Self> {
        let public_key = normalize_public_key_hex(public_key)?;
        let public_key_bytes = hex::decode(&public_key)?;
        let did_doc = Self::did_doc_from_public_key(&public_key_bytes)?;

        if let Some(expected_did) = expected_did {
            let expected_did = expected_did.trim();
            if expected_did != did_doc.id {
                bail!(
                    "notary DID/public key mismatch: response DID `{expected_did}` derives as `{}`",
                    did_doc.id
                );
            }
        }

        Ok(Self {
            url: url.to_owned(),
            version: "2".to_owned(),
            did_doc,
            operated_by: None,
            executed_on: None,
            did_statements: None,
            did_blobs: None,
            public_key: Some(public_key),
            binary_hash,
            binary_path,
        })
    }

    fn from_registration(url: &str, registration: RegistrationResponse) -> Result<Self> {
        let binary_hash = Some(normalize_hash_hex(
            "binary_hash",
            &registration.binary_hash,
            32,
        )?);
        Self::from_public_key(
            url,
            &registration.public_key,
            Some(&registration.did),
            binary_hash,
            registration.binary_path,
        )
    }

    /// Creates a new VCompNotarySigner by connecting to a verified computing notary service.
    ///
    /// This preserves the older public-key based constructor. New desktop notary integrations
    /// should prefer [`Self::create_for_binary`] so the signer stores the registration metadata
    /// returned by `POST /v1/registrations`.
    pub async fn create(url: &str, pub_key: Option<String>) -> Result<Self> {
        let pub_key = match pub_key {
            Some(pub_key) => pub_key,
            None => fetch_legacy_public_key(url).await?,
        };

        let mut signer = Self::from_public_key(url, &pub_key, None, None, None)?;
        if let Err(error) = signer.hydrate_legacy_registration_data().await {
            debug!("failed to fetch legacy VComp notary registration data: {error}");
        }

        Ok(signer)
    }

    /// Registers `binary_path` with the desktop notary and creates a signer for its DID.
    ///
    /// The desktop notary authorizes `/v1/sign` by the peer PID on a Unix-domain socket. The
    /// process that later uses this signer must be an exec of the registered binary after
    /// registration was created.
    pub async fn create_for_binary(url: &str, binary_path: &str) -> Result<Self> {
        let binary_path = binary_path.trim();
        if binary_path.is_empty() {
            bail!("binary_path cannot be empty");
        }

        let response = request_json(
            url,
            Method::POST,
            REGISTRATIONS_PATH,
            Some(json!({ "binary_path": binary_path })),
        )
        .await
        .context("failed to register binary with VComp notary")?;

        let registration: RegistrationResponse = serde_json::from_value(response)
            .context("invalid VComp notary registration response")?;
        let mut signer = Self::from_registration(url, registration)?;
        if signer.binary_path.is_none() {
            signer.binary_path = Some(binary_path.to_owned());
        }

        Ok(signer)
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
        if let Some(statements) = self.did_statements.clone() {
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

    async fn hydrate_legacy_registration_data(&mut self) -> Result<()> {
        let metadata = request_json(&self.url, Method::GET, "/get_dids", None).await?;
        self.operated_by = metadata
            .get("operatedBy")
            .and_then(|v| v.as_str())
            .map(String::from);
        self.executed_on = metadata
            .get("executedOn")
            .and_then(|v| v.as_str())
            .map(String::from);

        let manifest = request_json(&self.url, Method::GET, "/v1/did_registration", None).await?;
        self.did_statements = manifest["statements"].as_object().map(|obj| {
            obj.iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect::<HashMap<String, serde_json::Value>>()
        });

        self.did_blobs = manifest["blobs"]
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

        Ok(())
    }
}

#[async_trait]
impl Signer for VCompNotarySigner {
    async fn sign(&self, data: &[u8]) -> Result<[u8; 64]> {
        let response = request_json(
            &self.url,
            Method::POST,
            SIGN_PATH,
            Some(json!({
                "data": hex::encode(data),
                "hash": SIGN_HASH_ALG,
                "algo": SIGN_ALGO,
            })),
        )
        .await
        .context("failed to sign payload with VComp notary")?;

        let response: SignResponse =
            serde_json::from_value(response).context("invalid VComp notary sign response")?;

        if response.did.trim() != self.did_doc.id {
            bail!(
                "notary sign response DID `{}` does not match signer DID `{}`",
                response.did,
                self.did_doc.id
            );
        }

        let response_public_key = normalize_public_key_hex(&response.public_key)?;
        if let Some(public_key) = self.public_key.as_deref() {
            if response_public_key != public_key {
                bail!("notary sign response public key does not match signer public key");
            }
        }

        if let Some(binary_hash) = self.binary_hash.as_deref() {
            let response_binary_hash =
                normalize_hash_hex("binary_hash", &response.binary_hash, 32)?;
            if response_binary_hash != binary_hash {
                bail!("notary sign response binary hash does not match signer registration");
            }
        }

        let sig = hex::decode(response.signature.trim())
            .context("notary sign response signature is not valid hex")?;
        let sig: [u8; 64] = sig
            .try_into()
            .map_err(|_| anyhow!("notary sign response signature is not 64 bytes"))?;

        Ok(sig)
    }

    async fn get_did_doc(&self) -> Result<Option<Document>> {
        Ok(Some(self.did_doc.clone()))
    }
}

async fn fetch_legacy_public_key(url: &str) -> Result<String> {
    let response = request_json(url, Method::GET, "/v1/public_key", None)
        .await
        .context("failed to fetch VComp notary public key")?;

    response
        .get("public_key")
        .and_then(|v| v.as_str())
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow!("API response is missing string field `public_key`"))
}

async fn request_json(
    endpoint: &str,
    method: Method,
    path: &str,
    body: Option<Value>,
) -> Result<Value> {
    match parse_endpoint(endpoint)? {
        NotaryEndpoint::Unix {
            socket_path,
            authority,
        } => request_unix_json(socket_path, &authority, method, path, body).await,
        NotaryEndpoint::Tcp {
            address,
            authority,
            base_path,
        } => {
            let stream = TcpStream::connect(&address)
                .await
                .with_context(|| format!("failed to connect to VComp notary at {address}"))?;
            let path = join_endpoint_path(&base_path, path);
            request_http1_json(stream, &authority, method, &path, body).await
        }
    }
}

#[cfg(unix)]
async fn request_unix_json(
    socket_path: PathBuf,
    authority: &str,
    method: Method,
    path: &str,
    body: Option<Value>,
) -> Result<Value> {
    let stream = UnixStream::connect(&socket_path).await.with_context(|| {
        format!(
            "failed to connect to VComp notary socket {}",
            socket_path.display()
        )
    })?;
    request_http1_json(stream, authority, method, path, body).await
}

#[cfg(not(unix))]
async fn request_unix_json(
    socket_path: PathBuf,
    _authority: &str,
    _method: Method,
    _path: &str,
    _body: Option<Value>,
) -> Result<Value> {
    bail!(
        "Unix socket VComp notary endpoint `{}` is not supported on this platform",
        socket_path.display()
    );
}

async fn request_http1_json<I>(
    io: I,
    authority: &str,
    method: Method,
    path: &str,
    body: Option<Value>,
) -> Result<Value>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo::new(io);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .context("failed to initialize VComp notary HTTP connection")?;

    tokio::task::spawn(async move {
        if let Err(err) = conn.await {
            debug!("VComp notary HTTP connection failed: {err}");
        }
    });

    let body_bytes = body
        .map(|value| value.to_string())
        .unwrap_or_default()
        .into_bytes();

    let mut builder = Request::builder()
        .method(method.clone())
        .uri(path)
        .header(hyper::header::HOST, authority)
        .header(hyper::header::ACCEPT, "application/json");

    if !body_bytes.is_empty() {
        builder = builder
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .header(hyper::header::CONTENT_LENGTH, body_bytes.len().to_string());
    }

    let request = builder.body(Full::<Bytes>::from(body_bytes))?;
    debug!("VComp notary request: {method} {path}");

    let mut response = sender
        .send_request(request)
        .await
        .context("failed to send VComp notary request")?;
    let status = response.status();
    let bytes = response
        .body_mut()
        .collect()
        .await
        .context("failed to read VComp notary response body")?
        .to_bytes();

    if !status.is_success() {
        let detail = serde_json::from_slice::<Value>(&bytes)
            .ok()
            .as_ref()
            .and_then(|v| v.get("error"))
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .unwrap_or_else(|| String::from_utf8_lossy(&bytes).trim().to_owned());
        bail!(
            "VComp notary request {method} {path} failed: status={status} error={detail}"
        );
    }

    if bytes.is_empty() || status == StatusCode::NO_CONTENT {
        return Ok(Value::Null);
    }

    serde_json::from_slice(&bytes).context("failed to decode VComp notary JSON response")
}

fn parse_endpoint(raw: &str) -> Result<NotaryEndpoint> {
    let raw = raw.trim();
    if raw.is_empty() {
        bail!("VComp notary endpoint cannot be empty");
    }

    if let Some(socket_path) = raw.strip_prefix("unix://") {
        if socket_path.trim().is_empty() {
            bail!("VComp notary unix endpoint is missing socket path");
        }
        return Ok(NotaryEndpoint::Unix {
            socket_path: PathBuf::from(socket_path),
            authority: DEFAULT_UNIX_AUTHORITY.to_owned(),
        });
    }

    if raw.starts_with('/') {
        return Ok(NotaryEndpoint::Unix {
            socket_path: PathBuf::from(raw),
            authority: DEFAULT_UNIX_AUTHORITY.to_owned(),
        });
    }

    let uri = raw
        .parse::<hyper::Uri>()
        .with_context(|| format!("invalid VComp notary endpoint `{raw}`"))?;
    if uri.scheme_str() != Some("http") {
        bail!("VComp notary TCP endpoint must use http://");
    }

    let host = uri
        .host()
        .ok_or_else(|| anyhow!("VComp notary TCP endpoint is missing host"))?;
    let port = uri.port_u16().unwrap_or(80);
    let address = format!("{host}:{port}");
    let authority = uri
        .authority()
        .map(|authority| authority.as_str().to_owned())
        .ok_or_else(|| anyhow!("VComp notary TCP endpoint is missing authority"))?;
    let base_path = uri.path().trim_end_matches('/').to_owned();

    Ok(NotaryEndpoint::Tcp {
        address,
        authority,
        base_path,
    })
}

fn join_endpoint_path(base_path: &str, path: &str) -> String {
    let path = path.trim_start_matches('/');
    if base_path.is_empty() || base_path == "/" {
        format!("/{path}")
    } else {
        format!("{}/{path}", base_path.trim_end_matches('/'))
    }
}

fn normalize_public_key_hex(public_key: &str) -> Result<String> {
    let normalized = normalize_hash_hex("public_key", public_key, 33)?;
    let bytes = hex::decode(&normalized)?;
    let encoded_point = EncodedPoint::from_bytes(&bytes)
        .context("public_key is not a valid SEC1-encoded P-256 point")?;
    if !bool::from(encoded_point.is_compressed()) {
        bail!("public_key must be a SEC1-compressed P-256 point");
    }
    Ok(normalized)
}

fn normalize_hash_hex(field: &str, value: &str, len: usize) -> Result<String> {
    let value = value.trim();
    let bytes = hex::decode(value).with_context(|| format!("{field} is not valid hex"))?;
    if bytes.len() != len {
        bail!("{field} must be {len} bytes");
    }
    Ok(hex::encode(bytes))
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

    #[test]
    fn parses_plain_unix_socket_endpoint() {
        let endpoint = parse_endpoint("/tmp/eqty.sock").unwrap();
        assert_eq!(
            endpoint,
            NotaryEndpoint::Unix {
                socket_path: PathBuf::from("/tmp/eqty.sock"),
                authority: DEFAULT_UNIX_AUTHORITY.to_owned(),
            }
        );
    }

    #[test]
    fn parses_unix_scheme_endpoint() {
        let endpoint = parse_endpoint("unix:///tmp/eqty.sock").unwrap();
        assert_eq!(
            endpoint,
            NotaryEndpoint::Unix {
                socket_path: PathBuf::from("/tmp/eqty.sock"),
                authority: DEFAULT_UNIX_AUTHORITY.to_owned(),
            }
        );
    }

    #[test]
    fn parses_tcp_endpoint() {
        let endpoint = parse_endpoint("http://127.0.0.1:5287/api").unwrap();
        assert_eq!(
            endpoint,
            NotaryEndpoint::Tcp {
                address: "127.0.0.1:5287".to_owned(),
                authority: "127.0.0.1:5287".to_owned(),
                base_path: "/api".to_owned(),
            }
        );
        assert_eq!(join_endpoint_path("/api", "/v1/sign"), "/api/v1/sign");
    }

    #[test]
    fn registration_rejects_mismatched_did() {
        let signing_key = SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
        let public_key = signing_key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();

        let registration = RegistrationResponse {
            binary_hash: hex::encode([1u8; 32]),
            binary_path: Some("/usr/local/bin/viper".to_owned()),
            did: "did:key:znottherightkey".to_owned(),
            public_key: hex::encode(public_key),
        };

        let err = VCompNotarySigner::from_registration("/tmp/eqty.sock", registration).unwrap_err();
        assert!(err.to_string().contains("DID/public key mismatch"));
    }
}
