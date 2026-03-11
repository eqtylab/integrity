use std::{fmt, fs, path::PathBuf};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use base64::engine::{general_purpose::STANDARD as BASE64, Engine};
use did_key::Document;
use serde::{Deserialize, Serialize};

#[cfg(feature = "signer-akv")]
pub mod akv_signer;
#[cfg(feature = "signer-auth-service")]
pub mod auth_service_signer;
#[cfg(feature = "signer-ed25519")]
pub mod ed25519_signer;
#[cfg(any(feature = "signer-p256", feature = "signer-vcomp-notary"))]
pub(crate) mod p256_jwk;
#[cfg(feature = "signer-p256")]
pub mod p256_signer;
#[cfg(feature = "signer-secp256k1")]
pub mod secp256k1_signer;
#[cfg(feature = "signer-vcomp-notary")]
pub mod vcomp_notary;
#[cfg(feature = "signer-yubihsm")]
pub mod yubi_key;

#[cfg(feature = "signer-akv")]
pub use akv_signer::{AkvConfig, AkvSigner};
#[cfg(feature = "signer-auth-service")]
pub use auth_service_signer::AuthServiceSigner;
#[cfg(feature = "signer-ed25519")]
pub use ed25519_signer::Ed25519Signer;
#[cfg(feature = "signer-p256")]
pub use p256_signer::P256Signer;
#[cfg(feature = "signer-secp256k1")]
pub use secp256k1_signer::Secp256k1Signer;
#[cfg(feature = "signer-vcomp-notary")]
pub use vcomp_notary::VCompNotarySigner;
#[cfg(feature = "signer-yubihsm")]
pub use yubi_key::YubiHsmSigner;

/// Supported cryptographic key types for signing operations.
#[derive(Clone, Copy, PartialEq, Debug, Serialize, Deserialize)]
pub enum KeyType {
    #[cfg(feature = "signer-secp256k1")]
    #[serde(alias = "secp256k1")]
    SECP256K1,
    #[cfg(feature = "signer-p256")]
    #[serde(alias = "secp256r1")]
    SECP256R1,
    #[cfg(feature = "signer-ed25519")]
    #[serde(alias = "ed25519")]
    ED25519,
}

/// Enum over enabled signer implementations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignerType {
    #[cfg(feature = "signer-secp256k1")]
    SECP256K1(Secp256k1Signer),
    #[cfg(feature = "signer-ed25519")]
    ED25519(Ed25519Signer),
    #[cfg(feature = "signer-p256")]
    P256(P256Signer),
    #[cfg(feature = "signer-auth-service")]
    AuthService(AuthServiceSigner),
    #[cfg(feature = "signer-vcomp-notary")]
    VCompNotarySigner(VCompNotarySigner),
    #[cfg(feature = "signer-akv")]
    AKV(AkvSigner),
    #[cfg(feature = "signer-yubihsm")]
    YubiHsm2Signer(YubiHsmSigner),
}

impl fmt::Display for SignerType {
    fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(feature = "signer-secp256k1")]
            Self::SECP256K1(_) => write!(_f, "secp256k1"),
            #[cfg(feature = "signer-ed25519")]
            Self::ED25519(_) => write!(_f, "ed25519"),
            #[cfg(feature = "signer-p256")]
            Self::P256(_) => write!(_f, "p256"),
            #[cfg(feature = "signer-auth-service")]
            Self::AuthService(_) => write!(_f, "auth_service"),
            #[cfg(feature = "signer-vcomp-notary")]
            Self::VCompNotarySigner(_) => write!(_f, "vcomp_notary"),
            #[cfg(feature = "signer-akv")]
            Self::AKV(_) => write!(_f, "azure_key_vault"),
            #[cfg(feature = "signer-yubihsm")]
            Self::YubiHsm2Signer(_) => write!(_f, "yubihsm"),
            #[cfg(not(any(
                feature = "signer-secp256k1",
                feature = "signer-ed25519",
                feature = "signer-p256",
                feature = "signer-auth-service",
                feature = "signer-vcomp-notary",
                feature = "signer-akv",
                feature = "signer-yubihsm"
            )))]
            _ => unreachable!("SignerType has no enabled variants"),
        }
    }
}

impl SignerType {
    pub async fn sign(&self, _data: &[u8]) -> Result<[u8; 64]> {
        match self {
            #[cfg(feature = "signer-secp256k1")]
            Self::SECP256K1(signer) => signer.sign(_data).await,
            #[cfg(feature = "signer-ed25519")]
            Self::ED25519(signer) => signer.sign(_data).await,
            #[cfg(feature = "signer-p256")]
            Self::P256(signer) => signer.sign(_data).await,
            #[cfg(feature = "signer-auth-service")]
            Self::AuthService(signer) => signer.sign(_data).await,
            #[cfg(feature = "signer-vcomp-notary")]
            Self::VCompNotarySigner(signer) => signer.sign(_data).await,
            #[cfg(feature = "signer-akv")]
            Self::AKV(signer) => signer.sign(_data).await,
            #[cfg(feature = "signer-yubihsm")]
            Self::YubiHsm2Signer(signer) => signer.sign(_data).await,
            #[cfg(not(any(
                feature = "signer-secp256k1",
                feature = "signer-ed25519",
                feature = "signer-p256",
                feature = "signer-auth-service",
                feature = "signer-vcomp-notary",
                feature = "signer-akv",
                feature = "signer-yubihsm"
            )))]
            _ => Err(anyhow!("no signer implementation enabled at compile time")),
        }
    }

    pub fn get_did_doc(&self) -> Document {
        match self {
            #[cfg(feature = "signer-secp256k1")]
            Self::SECP256K1(signer) => signer.did_doc.clone(),
            #[cfg(feature = "signer-ed25519")]
            Self::ED25519(signer) => signer.did_doc.clone(),
            #[cfg(feature = "signer-p256")]
            Self::P256(signer) => signer.did_doc.clone(),
            #[cfg(feature = "signer-auth-service")]
            Self::AuthService(signer) => signer.did_doc.clone(),
            #[cfg(feature = "signer-vcomp-notary")]
            Self::VCompNotarySigner(signer) => signer.did_doc.clone(),
            #[cfg(feature = "signer-akv")]
            Self::AKV(signer) => signer.did_doc.clone(),
            #[cfg(feature = "signer-yubihsm")]
            Self::YubiHsm2Signer(signer) => signer.did_doc.clone(),
            #[cfg(not(any(
                feature = "signer-secp256k1",
                feature = "signer-ed25519",
                feature = "signer-p256",
                feature = "signer-auth-service",
                feature = "signer-vcomp-notary",
                feature = "signer-akv",
                feature = "signer-yubihsm"
            )))]
            _ => unreachable!("SignerType has no enabled variants"),
        }
    }
}

#[async_trait]
pub trait Signer {
    async fn sign(&self, data: &[u8]) -> Result<[u8; 64]>;
    async fn get_did_doc(&self) -> Result<Option<Document>>;
}

#[async_trait]
impl Signer for SignerType {
    async fn sign(&self, data: &[u8]) -> Result<[u8; 64]> {
        self.sign(data).await
    }

    async fn get_did_doc(&self) -> Result<Option<Document>> {
        Ok(Some(self.get_did_doc()))
    }
}

pub fn save_signer(signer: &SignerType, folder: PathBuf, name: &str) -> Result<()> {
    let signer_file = folder.join(name);
    let signer_str = serde_json::to_string(signer)?;
    let signer_base64 = BASE64.encode(signer_str);
    fs::write(signer_file, signer_base64).map_err(|e| anyhow!("Failed to write to file: {e}"))?;
    Ok(())
}

pub fn load_signer(signer_file: PathBuf) -> Result<SignerType> {
    let signer_base64 = fs::read_to_string(&signer_file)?;
    let signer_bytes = BASE64.decode(signer_base64)?;
    let signer_str = String::from_utf8(signer_bytes)?;
    let signer = serde_json::from_str(&signer_str)?;
    Ok(signer)
}
