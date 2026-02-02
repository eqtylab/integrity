/// Azure Key Vault signer implementation
pub mod akv_signer;
/// Auth service signer for remote signing operations
pub mod auth_service_signer;
/// Ed25519 elliptic curve signer
pub mod ed25519_signer;
/// P-256 (secp256r1) elliptic curve signer
pub mod p256_signer;
/// secp256k1 elliptic curve signer
pub mod secp256k1_signer;
/// Verified computing notary signer
pub mod vcomp_notary;
/// YubiHSM2 hardware security module signer
pub mod yubi_key;

use std::{fs, path::PathBuf};

pub use akv_signer::*;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
pub use auth_service_signer::*;
use base64::engine::{general_purpose::STANDARD as BASE64, Engine};
use did_key::Document;
pub use ed25519_signer::*;
pub use p256_signer::*;
pub use secp256k1_signer::*;
use serde::{Deserialize, Serialize};
use strum::Display;
pub use vcomp_notary::*;
pub use yubi_key::*;

/// Supported cryptographic key types for signing operations.
#[derive(
    Clone,
    Copy,
    PartialEq,
    Debug,
    Serialize,
    Deserialize,
    strum::EnumString,
    strum::Display,
    strum::VariantNames,
)]
pub enum KeyType {
    /// secp256k1 elliptic curve (used in Bitcoin/Ethereum)
    #[serde(alias = "secp256k1")]
    #[strum(serialize = "secp256k1")]
    SECP256K1,
    /// secp256r1/P-256 elliptic curve (NIST standard)
    #[serde(alias = "secp256r1")]
    #[strum(serialize = "secp256r1")]
    SECP256R1,
    /// Ed25519 elliptic curve (EdDSA)
    #[serde(alias = "ed25519")]
    #[strum(serialize = "ed25519")]
    ED25519,
}

/// Enum representing all supported signer implementations.
#[derive(Debug, Clone, Serialize, Deserialize, Display)]
pub enum SignerType {
    /// secp256k1 local signer
    #[strum(serialize = "secp256k1")]
    SECP256K1(Secp256k1Signer),
    /// Ed25519 local signer
    #[strum(serialize = "ed25519")]
    ED25519(Ed25519Signer),
    /// P-256 local signer
    #[strum(serialize = "p256")]
    P256(P256Signer),
    /// Verified computing notary remote signer
    #[strum(serialize = "vcomp_notary")]
    VCompNotarySigner(VCompNotarySigner),
    /// YubiHSM2 hardware signer
    #[strum(serialize = "yubihsm2")]
    YubiHsm2Signer(YubiHsmSigner),
    /// Auth service remote signer
    #[strum(serialize = "auth_service")]
    AuthService(AuthServiceSigner),
    /// Azure Key Vault signer
    #[strum(serialize = "azure key vault")]
    AKV(AkvSigner),
}

impl SignerType {
    /// Signs the provided data and returns a 64-byte signature.
    ///
    /// # Arguments
    ///
    /// * `data` - The data to sign.
    ///
    /// # Returns
    ///
    /// A 64-byte signature array.
    pub async fn sign(&self, data: &[u8]) -> Result<[u8; 64]> {
        match self {
            SignerType::SECP256K1(signer) => signer.sign(data).await,
            SignerType::ED25519(signer) => signer.sign(data).await,
            SignerType::P256(signer) => signer.sign(data).await,
            SignerType::AuthService(signer) => signer.sign(data).await,
            SignerType::YubiHsm2Signer(signer) => signer.sign(data).await,
            SignerType::VCompNotarySigner(signer) => signer.sign(data).await,
            SignerType::AKV(signer) => signer.sign(data).await,
        }
    }

    /// Returns the DID document associated with this signer.
    pub fn get_did_doc(&self) -> Document {
        match self {
            SignerType::SECP256K1(signer) => signer.did_doc.clone(),
            SignerType::ED25519(signer) => signer.did_doc.clone(),
            SignerType::P256(signer) => signer.did_doc.clone(),
            SignerType::AuthService(signer) => signer.did_doc.clone(),
            SignerType::YubiHsm2Signer(signer) => signer.did_doc.clone(),
            SignerType::VCompNotarySigner(signer) => signer.did_doc.clone(),
            SignerType::AKV(signer) => signer.did_doc.clone(),
        }
    }
}

/// Trait for cryptographic signing operations.
#[async_trait]
pub trait Signer {
    /// Signs the provided data and returns a 64-byte signature.
    ///
    /// # Arguments
    ///
    /// * `data` - The data to sign.
    ///
    /// # Returns
    ///
    /// A 64-byte signature array.
    async fn sign(&self, data: &[u8]) -> Result<[u8; 64]>;

    /// Returns the DID document associated with this signer, if available.
    ///
    /// # Returns
    ///
    /// `Some(Document)` if the signer has an associated DID document, `None` otherwise.
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

/// Saves a signer to a file in the specified folder.
///
/// The signer is serialized to JSON and base64-encoded before writing.
///
/// # Arguments
///
/// * `signer` - The signer to save.
/// * `folder` - The directory to save the signer file in.
/// * `name` - The filename for the signer file.
///
/// # Returns
///
/// `Ok(())` on success, or an error if the file could not be written.
pub fn save_signer(signer: &SignerType, folder: PathBuf, name: &str) -> Result<()> {
    let signer_file = folder.join(name);

    let signer_str = serde_json::to_string(&signer)?;

    let signer_base64 = BASE64.encode(signer_str);
    fs::write(signer_file, signer_base64).map_err(|e| anyhow!("Failed to write to file: {e}"))?;
    Ok(())
}

/// Loads a signer from a file.
///
/// The file is expected to contain a base64-encoded JSON representation of a signer.
///
/// # Arguments
///
/// * `signer_file` - Path to the signer file.
///
/// # Returns
///
/// The deserialized `SignerType`.
pub fn load_signer(signer_file: PathBuf) -> Result<SignerType> {
    let signer_base64 = fs::read_to_string(&signer_file)?;
    let signer_bytes = BASE64.decode(signer_base64)?;
    let signer_str = String::from_utf8(signer_bytes)?;
    let signer = serde_json::from_str(&signer_str)?;
    Ok(signer)
}

#[cfg(test)]
mod tests {
    use base64::Engine;

    use super::*;

    #[tokio::test]
    async fn ed25519_create() {
        let _ = env_logger::builder().is_test(true).try_init();
        let signer_name = "random";
        let folder = "./tmp/ed255";
        let _ = fs::remove_dir_all(folder);
        let _ = fs::create_dir_all(folder);

        let signer = Ed25519Signer::create().unwrap();
        let signer_type = SignerType::ED25519(signer);
        let result = save_signer(&signer_type, PathBuf::from(&folder), signer_name);

        // Assert the function succeeded
        assert!(result.is_ok(), "Failed to save signer: {result:?}");

        let signer_result = load_signer("./tmp/ed255/random".into());
        assert!(
            signer_result.is_ok(),
            "Failed to load signer: {signer_result:?}"
        );

        let signer = signer_result.unwrap();
        let data = "hello world".as_bytes();

        match signer {
            SignerType::ED25519(ed25519_signer) => {
                let sig = ed25519_signer.sign(data).await.unwrap();
                assert_eq!(sig.len(), 64, "Signature should be 64 bytes");
            }
            _ => panic!("Expected ED25519 signer"),
        }
    }

    #[tokio::test]
    async fn ed25519_import() {
        let _ = env_logger::builder().is_test(true).try_init();
        let signer_name = "imported";
        let folder = "./tmp/ed255";
        let _ = fs::remove_dir_all(folder);
        let _ = fs::create_dir_all(folder);

        // Use a raw 32-byte Ed25519 secret key (hex encoded for readability)
        let secret_key_hex = "787b76d96345bd45e88827f1fb9b4235bb847128c18de11ab7e395789578c578";
        let secret_key_bytes = hex::decode(secret_key_hex).unwrap();
        assert_eq!(
            secret_key_bytes.len(),
            32,
            "Ed25519 secret key must be 32 bytes"
        );
        let signer = Ed25519Signer::import(&secret_key_bytes).unwrap();
        let signer_type = SignerType::ED25519(signer);
        let result = save_signer(&signer_type, PathBuf::from(&folder), signer_name);

        // Assert the function succeeded
        assert!(result.is_ok(), "Failed to save signer: {result:?}");

        let signer_result = load_signer("./tmp/ed255/imported".into());
        assert!(
            signer_result.is_ok(),
            "Failed to load signer: {signer_result:?}"
        );

        let signer = signer_result.unwrap();
        let data = "hello world".as_bytes();

        match signer {
            SignerType::ED25519(ed25519_signer) => {
                let sig = ed25519_signer.sign(data).await.unwrap();
                assert_eq!(sig.len(), 64, "Signature should be 64 bytes");

                // You can also get it as base64
                let sig_base64 = BASE64.encode(sig);

                let expected_sig = "TikhoZ7lWQnHd9fniTckq5jlRNUusAXkAcS/u/XXRKqbdH2IwQyZQTeHGeHrz6SnWQa4FNQ2Ch40a4PPxRzpBA==";
                assert_eq!(
                    sig_base64, expected_sig,
                    "Signature doesn't match expected value"
                );
            }
            _ => panic!("Expected ED25519 signer"),
        }
    }

    #[tokio::test]
    async fn secp265k1_create() {
        let _ = env_logger::builder().is_test(true).try_init();
        let signer_name = "random";
        let folder = "./tmp/secp256";
        let _ = fs::remove_dir_all(folder);
        let _ = fs::create_dir_all(folder);

        let signer = Secp256k1Signer::create().unwrap();
        let signer_type = SignerType::SECP256K1(signer);
        let result = save_signer(&signer_type, PathBuf::from(&folder), signer_name);

        assert!(result.is_ok(), "Failed to save signer: {result:?}");

        let signer_result = load_signer("./tmp/secp256/random".into());
        assert!(
            signer_result.is_ok(),
            "Failed to load signer: {signer_result:?}"
        );

        let signer = signer_result.unwrap();
        let data = "hello world".as_bytes();

        match signer {
            SignerType::SECP256K1(signer) => {
                let sig = signer.sign(data).await.unwrap();
                assert_eq!(sig.len(), 64, "Signature should be 64 bytes");
            }
            _ => panic!("Expected SECP256K1 signer"),
        }
    }

    #[tokio::test]
    async fn secp256k1_import() {
        let _ = env_logger::builder().is_test(true).try_init();
        let signer_name = "imported";
        let folder = "./tmp/secp256";
        let _ = fs::remove_dir_all(folder);
        let _ = fs::create_dir_all(folder);

        let secret_key_hex = "787b76d96345bd45e88827f1fb9b4235bb847128c18de11ab7e395789578c578";
        let secret_key_bytes = hex::decode(secret_key_hex).unwrap();
        assert_eq!(
            secret_key_bytes.len(),
            32,
            "Secp256k1 secret key must be 32 bytes"
        );
        let signer = Secp256k1Signer::import(&secret_key_bytes).unwrap();
        let signer_type = SignerType::SECP256K1(signer);
        let result = save_signer(&signer_type, PathBuf::from(&folder), signer_name);

        // Assert the function succeeded
        assert!(result.is_ok(), "Failed to save signer: {result:?}");

        let signer_result = load_signer("./tmp/secp256/imported".into());
        assert!(
            signer_result.is_ok(),
            "Failed to load signer: {signer_result:?}"
        );

        let signer = signer_result.unwrap();
        let data = "hello world".as_bytes();

        match signer {
            SignerType::SECP256K1(signer) => {
                let sig = signer.sign(data).await.unwrap();
                assert_eq!(sig.len(), 64, "Signature should be 64 bytes");

                let sig_base64 = BASE64.encode(sig);

                let expected_sig = "uV6iVhAWOkN7tiZs2LNp3t/0DMgBxE/pvl7/ihqQZfsRbbiiU+a0N455xaNdSOuV4pShi9Zi5fd6T8Q2O1xw7A==";
                assert_eq!(
                    sig_base64, expected_sig,
                    "Signature doesn't match expected value"
                );
            }
            _ => panic!("Expected SECP256K1 signer"),
        }
    }

    #[tokio::test]
    async fn signer_type_serialize() {
        let secp256k1_signer = SignerType::SECP256K1(Secp256k1Signer::create().unwrap());
        assert_eq!(format!("{secp256k1_signer}"), "secp256k1".to_owned());

        let ed25519_signer = SignerType::ED25519(Ed25519Signer::create().unwrap());
        assert_eq!(format!("{ed25519_signer}"), "ed25519".to_owned());
    }
}
