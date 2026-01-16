use std::{collections::HashMap, fs, path::PathBuf};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use base64::engine::{general_purpose::STANDARD as BASE64, Engine};
use did_key::{DIDCore, Document, Generate, P256KeyPair};
use http_body_util::{BodyExt, Full};
use hyper::{body::Bytes, Request};
use hyper_util::rt::TokioIo;
use log::debug;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::net::TcpStream;

use crate::{cid::strip_urn_cid, signer::Signer};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VCompNotarySigner {
    pub version: String,
    pub url: String,
    pub did_doc: Document,
    pub operated_by: Option<String>,
    pub executed_on: Option<String>,
    pub did_statements: Option<HashMap<String, serde_json::Value>>,
    pub did_blobs: Option<HashMap<String, Vec<u8>>>,
}

impl VCompNotarySigner {
    pub async fn create(url: &str, pub_key: Option<String>) -> Result<Self> {
        let client = reqwest::Client::new();

        let pub_key = if let Some(pub_key) = pub_key {
            pub_key
        } else {
            client
                .get(format!("{url}/v1/public_key"))
                .send()
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
        let key_pair = P256KeyPair::from_public_key(&pub_key);

        let did_doc = key_pair.get_did_document(did_key::Config {
            use_jose_format: true,
            serialize_secrets: true,
        });

        let response = client
            .get(format!("{url}/get_dids"))
            .send()
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

        let request = client.get(format!("{url}/v1/did_registration"));
        log::trace!("Downloading VCOMP DID Registration. {request:?}");

        let manifest = request.send().await?.json::<Value>().await?;

        let signer = VCompNotarySigner {
            url: url.to_owned(),
            version: "1".to_owned(),
            did_doc,
            operated_by,
            executed_on,
            did_statements: manifest["statements"].as_object().map(|obj| {
                obj.iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect::<HashMap<String, serde_json::Value>>()
            }),

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
        };

        Ok(signer)
    }

    /// Copies the signers DID Statements and Blobs to the specified directories
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
}

#[async_trait]
impl Signer for VCompNotarySigner {
    async fn sign(&self, data: &[u8]) -> Result<[u8; 64]> {
        let url = self.url.parse::<hyper::Uri>().unwrap();
        debug!("URL: {url:?}");

        // Get the host and the port
        let host = url.host().expect("uri has no host");
        debug!("HOST: {host:?}");
        let port = url.port_u16().unwrap_or(8000);
        debug!("PORT: {port:?}");

        let address = format!("{}:{}", host, port);
        debug!("ADDRESS: {address:?}");

        // Open a TCP connection to the remote host
        let stream = TcpStream::connect(address).await?;

        // Use an adapter to access something implementing `tokio::io` traits as if they implement
        // `hyper::rt` IO traits.
        let io = TokioIo::new(stream);

        // Create the Hyper client
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;

        // Spawn a task to poll the connection, driving the HTTP state
        tokio::task::spawn(async move {
            if let Err(err) = conn.await {
                println!("Connection failed: {:?}", err);
            }
        });

        // The authority of our URL will be the hostname of the httpbin remote
        let authority = url.authority().unwrap().clone();

        // turn &[u8] into hex
        let data_hex = hex::encode(data);

        // build JSON payload
        let payload = json!({
            "data": data_hex
        })
        .to_string();

        // Create an HTTP request with an empty body and a HOST header
        let req = Request::builder()
            .method("POST")
            .uri("/v1/sign")
            .header(hyper::header::HOST, authority.as_str())
            .header(hyper::header::ACCEPT, "application/json")
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .body(Full::<Bytes>::from(payload))?;
        debug!("REQ: {req:?}");
        let mut res = sender.send_request(req).await?;

        let bytes = res.body_mut().collect().await?.to_bytes();
        let v: Value = serde_json::from_slice(&bytes)?;

        let sig_hex = v
            .get("signature")
            .and_then(|s| s.as_str())
            .expect("missing signature");
        let sig = hex::decode(sig_hex).expect("invalid hex");
        let sig: [u8; 64] = sig.try_into().expect("signature not 64 bytes");

        Ok(sig)
    }

    async fn get_did_doc(&self) -> Result<Option<Document>> {
        Ok(Some(self.did_doc.clone()))
    }
}
