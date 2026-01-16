use std::sync::Arc;

use anyhow::{anyhow, bail, Result};
use async_trait::async_trait;
use azure_core::Url;
use azure_identity::ClientSecretCredential;
use azure_security_keyvault::{
    prelude::{JsonWebKey, SignatureAlgorithm},
    KeyClient,
};
use base64::engine::{general_purpose::URL_SAFE_NO_PAD as BASE64_URL_NO_PAD, Engine};
use did_key::{DIDCore, Document, Generate, Secp256k1KeyPair};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::signer::Signer;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct AkvConfig {
    pub client_secret: String,
    pub tenant_id: String,
    pub client_id: String,
    pub vault_url: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AkvSigner {
    key_name: String,
    pub did_doc: Document,
    config: AkvConfig,
}

impl AkvSigner {
    fn new_key_client(&self) -> Result<KeyClient> {
        let AkvConfig {
            tenant_id,
            client_id,
            client_secret,
            vault_url,
        } = &self.config;

        let client = Arc::new(Client::new());
        let credential = Arc::new(ClientSecretCredential::new(
            client,
            Url::parse("https://login.microsoftonline.com")?,
            tenant_id.clone(),
            client_id.clone(),
            client_secret.clone(),
        ));

        log::trace!("key client created");
        Ok(KeyClient::new(vault_url, credential)?)
    }

    pub async fn create(config: &AkvConfig, key_name: String) -> Result<Self> {
        let client = Arc::new(Client::new());

        log::debug!("creating AkvSigner");
        let AkvConfig {
            tenant_id,
            client_id,
            client_secret,
            vault_url,
        } = config;

        let credential = Arc::new(ClientSecretCredential::new(
            client,
            Url::parse("https://login.microsoftonline.com")?,
            tenant_id.clone(),
            client_id.clone(),
            client_secret.clone(),
        ));

        log::debug!("creating key client");
        let key_client = KeyClient::new(vault_url, credential)?;
        log::debug!("retrieving public key");
        let key = key_client.get(&key_name).await?.key;
        log::debug!("generating DID Doc from azure key");
        let did_doc = generate_did_doc_for_jwk(key).await?;

        Ok(AkvSigner {
            key_name,
            did_doc,
            config: config.clone(),
        })
    }
}

async fn generate_did_doc_for_jwk(key: JsonWebKey) -> Result<Document> {
    let curve = key
        .curve_name
        .ok_or_else(|| anyhow!("Unable to determine the curve type for the key"))?;

    if curve != "P-256K" {
        bail!("The key is not of type P-256k")
    }

    let (x, y) = match (key.x, key.y) {
        (Some(x), Some(y)) => (x, y),
        _ => bail!("Unable to determine the x and y coordinates for key"),
    };

    let mut pub_key: Vec<u8> = x;
    pub_key.insert(0, if y[y.len() - 1] % 2 == 0 { 0x2 } else { 0x3 });

    let mut array_u8: [u8; 33] = [0; 33];
    array_u8.copy_from_slice(&pub_key);

    let key_pair = Secp256k1KeyPair::from_public_key(&array_u8);

    let did_doc = key_pair.get_did_document(did_key::Config {
        use_jose_format: true,
        serialize_secrets: true,
    });

    Ok(did_doc)
}

#[async_trait]
impl Signer for AkvSigner {
    async fn sign(&self, data: &[u8]) -> Result<[u8; 64]> {
        log::debug!("Siging data");
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hasher.finalize();

        let encoded_hash = BASE64_URL_NO_PAD.encode(hash);
        let key_client = self.new_key_client()?;

        log::trace!("Signing data with AKV. {}", &self.key_name);
        let sign_result = key_client
            .sign(
                self.key_name.clone(),
                SignatureAlgorithm::ES256K,
                encoded_hash,
            )
            .await?;

        log::trace!("Signing result: {sign_result:?}");
        if sign_result.signature.len() != 64 {
            return Err(anyhow!(
                "Expected 64-byte signature, got {}",
                sign_result.signature.len()
            ));
        }

        let sig: [u8; 64] = sign_result
            .signature
            .try_into()
            .map_err(|_| anyhow!("Failed to convert signature to [u8; 64]"))?;

        Ok(sig)
    }

    async fn get_did_doc(&self) -> Result<Option<Document>> {
        Ok(Some(self.did_doc.clone()))
    }
}
