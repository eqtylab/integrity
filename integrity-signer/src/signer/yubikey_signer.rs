use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use base64::engine::{general_purpose::STANDARD as BASE64, Engine};
use did_key::{DIDCore, Document, Generate, P256KeyPair};
use p256::{ecdsa::Signature, EncodedPoint};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x509_cert::der::Encode;
use yubikey::{
    certificate::Certificate,
    piv::{self, AlgorithmId, ManagementAlgorithmId, SlotId},
    Serial, YubiKey,
};

use crate::signer::{p256_jwk::fix_p256_jwk_from_encoded_point, Signer};

/// Signer implementation backed by a YubiKey PIV slot configured with an ECC P-256 key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct YubiKeySigner {
    /// PIV slot identifier (for example, `SlotId::Signature`).
    #[serde(with = "slot_id_serde")]
    pub slot: SlotId,
    /// Optional serial to target a specific YubiKey when multiple are connected.
    pub serial: Option<u32>,
    /// Optional PIN used before each signing operation.
    pub pin: Option<String>,
    /// DID document derived from the slot's public key.
    pub did_doc: Document,
}

/// Evidence bundle for a YubiKey-backed PIV signer key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct YubikeyEvidenceBundle {
    /// DER certificate for the signing key in the configured slot (base64 encoded).
    pub signing_key_cert_der_base64: String,
    /// DER certificate for the YubiKey-resident issuer key in slot `f9` (base64 encoded).
    pub signing_key_cert_issuer_der_base64: String,
}

impl YubiKeySigner {
    /// Creates a new signer from an existing PIV key slot on a YubiKey.
    ///
    /// The selected slot must contain an ECC P-256 key.
    pub fn create(slot: SlotId, serial: Option<u32>, pin: Option<String>) -> Result<Self> {
        let mut yubikey = Self::open(serial)?;

        if let Some(pin) = pin.as_deref() {
            Self::verify_pin(&mut yubikey, pin)?;
        }

        let did_doc = Self::did_doc_from_slot(&mut yubikey, slot)?;

        Ok(Self {
            slot,
            serial,
            pin,
            did_doc,
        })
    }

    /// Signs a payload with the configured YubiKey slot and returns a raw 64-byte ECDSA signature.
    ///
    /// YubiKey PIV ECDSA signing expects a digest-sized input. For P-256 this is SHA-256.
    pub fn sign_sync(&self, data: &[u8]) -> Result<[u8; 64]> {
        let mut yubikey = Self::open(self.serial)?;

        if let Some(pin) = self.pin.as_deref() {
            Self::verify_pin(&mut yubikey, pin)?;
        }

        let digest = Sha256::digest(data);
        let signature_der = piv::sign_data(
            &mut yubikey,
            digest.as_slice(),
            AlgorithmId::EccP256,
            self.slot,
        )
        .context("failed to sign payload with YubiKey PIV slot")?;

        let signature = Signature::from_der(signature_der.as_slice())
            .context("failed to decode YubiKey signature as DER-encoded ECDSA P-256")?;

        let signature = signature
            .to_bytes()
            .try_into()
            .context("failed to convert YubiKey signature to raw 64-byte format")?;

        Ok(signature)
    }

    /// Collects attestation certificates and metadata for the configured YubiKey slot.
    pub fn evidence_bundle_sync(&self) -> Result<YubikeyEvidenceBundle> {
        let mut yubikey = Self::open(self.serial)?;

        if let Some(pin) = self.pin.as_deref() {
            Self::verify_pin(&mut yubikey, pin)?;
        }

        let slot_attestation_der = piv::attest(&mut yubikey, self.slot)
            .context("failed to generate YubiKey slot attestation certificate")?;
        let f9_certificate = Certificate::read(&mut yubikey, SlotId::Attestation)
            .context("failed to read YubiKey slot f9 attestation certificate")?;
        let f9_der = f9_certificate
            .cert
            .to_der()
            .context("failed to serialize YubiKey slot f9 attestation certificate")?;

        Ok(YubikeyEvidenceBundle {
            signing_key_cert_der_base64: BASE64.encode(slot_attestation_der.as_slice()),
            signing_key_cert_issuer_der_base64: BASE64.encode(f9_der),
        })
    }

    fn did_doc_from_slot(yubikey: &mut YubiKey, slot: SlotId) -> Result<Document> {
        let metadata =
            piv::metadata(yubikey, slot).context("failed to read YubiKey slot metadata")?;

        match metadata.algorithm {
            ManagementAlgorithmId::Asymmetric(AlgorithmId::EccP256) => {}
            other => {
                return Err(anyhow!(
                    "slot {slot:?} is not an ECC P-256 key slot (found {other:?})"
                ));
            }
        }

        let public = metadata
            .public
            .ok_or_else(|| anyhow!("slot {slot:?} does not expose a public key"))?;
        let encoded_point = EncodedPoint::from_bytes(public.subject_public_key.raw_bytes())
            .map_err(|e| anyhow!("invalid P-256 public key in slot {slot:?}: {e}"))?;

        let key_pair = P256KeyPair::from_public_key(encoded_point.as_bytes());
        let mut did_doc = key_pair.get_did_document(did_key::Config {
            use_jose_format: true,
            serialize_secrets: false,
        });
        fix_p256_jwk_from_encoded_point(&mut did_doc, &encoded_point, None)?;

        Ok(did_doc)
    }

    fn open(serial: Option<u32>) -> Result<YubiKey> {
        match serial {
            Some(serial) => YubiKey::open_by_serial(Serial(serial))
                .with_context(|| format!("failed to open YubiKey with serial {serial}")),
            None => YubiKey::open().context("failed to open YubiKey"),
        }
    }

    fn verify_pin(yubikey: &mut YubiKey, pin: &str) -> Result<()> {
        yubikey
            .verify_pin(pin.as_bytes())
            .context("YubiKey PIN verification failed")?;

        Ok(())
    }
}

#[async_trait]
impl Signer for YubiKeySigner {
    async fn sign(&self, data: &[u8]) -> Result<[u8; 64]> {
        let signature = self.sign_sync(data)?;

        Ok(signature)
    }

    async fn get_did_doc(&self) -> Result<Option<Document>> {
        Ok(Some(self.did_doc.clone()))
    }
}

mod slot_id_serde {
    use serde::{Deserialize, Deserializer, Serializer};
    use yubikey::piv::SlotId;

    pub fn serialize<S>(slot: &SlotId, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u8((*slot).into())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<SlotId, D::Error>
    where
        D: Deserializer<'de>,
    {
        let slot = u8::deserialize(deserializer)?;
        SlotId::try_from(slot).map_err(|_| {
            <D::Error as serde::de::Error>::custom(format!(
                "invalid PIV slot identifier: 0x{slot:02x}"
            ))
        })
    }
}
