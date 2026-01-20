use core::default::Default;

#[cfg(not(target_arch = "wasm32"))]
use anyhow::anyhow;
use anyhow::{bail, Result};
#[cfg(not(target_arch = "wasm32"))]
use base64::engine::{general_purpose::URL_SAFE_NO_PAD as BASE64_URL_NO_PAD, Engine};
#[cfg(not(target_arch = "wasm32"))]
use chrono::{DateTime, Utc};
#[cfg(not(target_arch = "wasm32"))]
use did_key::KeyFormat;
use did_method_key::DIDKey;
#[cfg(not(target_arch = "wasm32"))]
use serde::ser::{Serialize, SerializeStruct, Serializer};
#[cfg(not(target_arch = "wasm32"))]
use serde_json::Value;
use ssi::{jsonld::ContextLoader, vc::Credential};
#[cfg(not(target_arch = "wasm32"))]
use ssi::{
    jwk::JWK,
    ldp::{ProofPreparation, ProofSuite, ProofSuiteType, SigningInput},
    one_or_many::OneOrMany,
    vc::{LinkedDataProofOptions, ProofPurpose, VCDateTime, URI},
};

#[cfg(not(target_arch = "wasm32"))]
use crate::signer::SignerType;

/// Simplified verifiable credential
///
/// A lightweight W3C Verifiable Credential implementation for issuing
/// and signing credentials with DIDs and linked data proofs.
#[derive(Debug, Default)]
#[cfg(not(target_arch = "wasm32"))]
pub struct VerifiableCredential {
    /// Unique identifier for this credential
    pub id: Option<String>,
    /// DID of the credential issuer
    pub issuer: String,
    /// When the credential was issued (ISO 8601 format)
    pub issuance_date: Option<String>,
    /// When the credential becomes valid (ISO 8601 format)
    pub valid_from: Option<String>,
    /// DID or identifier of the credential subject
    pub subject: String,
    /// Additional evidence supporting the credential claims
    pub evidence: Option<Value>,
    /// When the credential expires
    pub expiration_date: Option<VCDateTime>,
}

#[cfg(not(target_arch = "wasm32"))]
impl VerifiableCredential {
    /// Creates a verifiable credential from a DID document
    ///
    /// # Arguments
    /// * `subject` - The credential subject identifier
    /// * `did_doc` - DID document of the issuer
    ///
    /// # Returns
    /// A new verifiable credential with the issuer set from the DID document
    pub fn from_did_doc(subject: &str, did_doc: &did_key::Document) -> Self {
        VerifiableCredential {
            issuer: did_doc.id.clone(),
            subject: subject.to_owned(),
            ..Default::default()
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl TryInto<Credential> for VerifiableCredential {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<Credential> {
        let vc_str = serde_json::to_string(&self)?;
        let unsigned_vc: Credential = Credential::from_json_unsigned(&vc_str)?;
        Ok(unsigned_vc)
    }
}

/// Custom serializer to convert VerifiableCredential struct to the expected Credential JSON representation
#[cfg(not(target_arch = "wasm32"))]
impl Serialize for VerifiableCredential {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("VerifiableCredential", 7)?;

        state.serialize_field(
            "@context",
            &vec![
                "https://www.w3.org/ns/credentials/v2",
                "https://w3id.org/security/v2",
            ],
        )?;

        state.serialize_field("type", &vec!["VerifiableCredential"])?;

        let id = self
            .id
            .clone()
            .unwrap_or_else(|| format!("urn:uuid:{}", uuid::Uuid::new_v4()));
        state.serialize_field("id", &id)?;

        state.serialize_field("issuer", &self.issuer)?;

        // backdate by 1 hour so VCs are valid immediately even between systems with slightly different clock drifts
        let now = chrono::Utc::now() - chrono::Duration::hours(1);
        let issuance_date = match &self.issuance_date {
            Some(date) => {
                let date = chrono::DateTime::parse_from_rfc3339(date).map_err(|_| {
                    serde::ser::Error::custom("failed to parse 'issuance_date' field")
                })?;
                date.with_timezone(&chrono::Utc)
            }
            None => now,
        };
        let issuance_date_str = issuance_date.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        state.serialize_field("issuanceDate", &issuance_date_str)?;

        let valid_from = match &self.valid_from {
            Some(date) => {
                let date = chrono::DateTime::parse_from_rfc3339(date)
                    .map_err(|_| serde::ser::Error::custom("failed to parse 'valid_from' field"))?;
                date.with_timezone(&chrono::Utc)
            }
            None => now,
        };
        let valid_from_str = valid_from.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        state.serialize_field("validFrom", &valid_from_str)?;

        let credential_subject =
            if let Ok(parsed_json) = serde_json::from_str::<Value>(&self.subject) {
                // If subject is valid JSON, use it as the credential subject
                parsed_json
            } else {
                // Otherwise, wrap it as {"id": subject}
                serde_json::json!({"id": self.subject})
            };
        state.serialize_field("credentialSubject", &credential_subject)?;

        if let Some(ref evidence) = self.evidence {
            state.serialize_field("evidence", evidence)?;
        }

        if let Some(ref expiration) = self.expiration_date {
            state.serialize_field("validUntil", expiration)?;
        }

        state.end()
    }
}

/// Creates and signs a Verifiable Credential.
///
/// # Arguments
///
/// * `subject` - The credential subject identifier (DID or other identifier).
/// * `signer` - The signer to use for signing the credential.
///
/// # Returns
///
/// A signed `Credential` with a linked data proof.
#[cfg(not(target_arch = "wasm32"))]
pub async fn issue_vc(subject: &str, signer: SignerType) -> Result<Credential> {
    log::debug!("Issuing VC for '{subject}'");
    let did_doc = signer.get_did_doc();
    let vc = VerifiableCredential::from_did_doc(subject, &did_doc);
    log::trace!("Unsigned VC: {}", serde_json::to_string_pretty(&vc)?);
    sign_vc(&vc.try_into()?, signer).await
}

/// Creates a VC proof and signs the provided credential.
///
/// # Arguments
///
/// * `unsigned_vc` - The unsigned credential to sign.
/// * `signer` - The signer to use for creating the proof signature.
///
/// # Returns
///
/// A signed `Credential` with the proof attached.
#[cfg(not(target_arch = "wasm32"))]
pub async fn sign_vc(unsigned_vc: &Credential, signer: SignerType) -> Result<Credential> {
    log::debug!("Signing VC with {signer:?}");
    let proof_date = if let Some(date) = unsigned_vc.issuance_date.clone() {
        Some(date.into())
    } else {
        // backdate by 1 hour so VCs are valid immediately even between systems with slightly different clock drifts
        Some(chrono::Utc::now() - chrono::Duration::hours(1))
    };

    log::trace!("Getting DID Doc from signer");
    let did_doc = signer.get_did_doc();
    let proof_preparation = &prepare_vc_proof(&did_doc, unsigned_vc, proof_date).await?;

    let ProofPreparation {
        proof,
        signing_input,
        ..
    } = proof_preparation;

    let signature = {
        let data = match signing_input {
            SigningInput::Bytes(bytes) => bytes,
            _ => bail!("Invalid signing input type. Expected bytes."),
        };
        let data = data.0.as_slice();

        let signature = signer.sign(data).await?;

        BASE64_URL_NO_PAD.encode(signature)
    };

    let proof = proof.type_.complete(proof_preparation, &signature).await?;

    let signed_vc = Credential {
        proof: Some(OneOrMany::One(proof)),
        ..unsigned_vc.clone()
    };

    Ok(signed_vc)
}

/// Verifies a Verifiable Credential.
///
/// # Arguments
///
/// * `vc` - JSON string representation of the credential to verify.
///
/// # Returns
///
/// A formatted string containing the verification result on success.
pub async fn verify_vc(vc: &str) -> Result<String> {
    let vc = Credential::from_json_unsigned(vc)?;

    let result = vc
        .verify(None, &DIDKey, &mut ContextLoader::default())
        .await;

    if !result.errors.is_empty() {
        bail!("VC verification failed. {:?}", result.errors);
    }

    Ok(format!(
        "VC verification result:\n{}",
        serde_json::to_string_pretty(&result)?
    ))
}

#[cfg(not(target_arch = "wasm32"))]
async fn prepare_vc_proof(
    did: &did_key::Document,
    unsigned_vc: &Credential,
    creation_date: Option<DateTime<Utc>>,
) -> Result<ProofPreparation> {
    log::trace!("Preparing VC Proof");
    let key_type = match &did.verification_method[0].public_key {
        Some(KeyFormat::JWK(jwk)) => jwk.curve.clone(),
        _ => {
            log::error!("Unhandled key type in DID verification method");
            bail!("Unhandled key type in DID verification method");
        }
    };

    let proof_type = match key_type.as_str() {
        "Ed25519" => ProofSuiteType::Ed25519Signature2018,
        "secp256k1" => ProofSuiteType::EcdsaSecp256k1Signature2019,
        "P-256" => ProofSuiteType::EcdsaSecp256r1Signature2019,
        _ => {
            log::error!("Unknown key type for signing");
            bail!("Unknown key type for signing");
        }
    };

    let verification_method = did
        .verification_method
        .first()
        .ok_or_else(|| anyhow!("Verification method not found in DID Document"))?;

    let jwk = match &verification_method.public_key {
        Some(KeyFormat::JWK(jwk)) => {
            log::trace!("Converting did_key JWK to ssi JWK");
            // Convert did_key JWK to ssi JWK via JSON serialization
            let jwk_json = serde_json::to_value(jwk)?;
            serde_json::from_value::<JWK>(jwk_json)?
        }
        _ => {
            log::error!("Public key not found or not in JWK format in DID verification method");
            bail!("Public key not found or not in JWK format in DID verification method");
        }
    };

    let proof_preparation = unsigned_vc
        .prepare_proof(
            &jwk,
            &LinkedDataProofOptions {
                type_: Some(proof_type),
                proof_purpose: Some(ProofPurpose::AssertionMethod),
                verification_method: Some(URI::String(verification_method.id.clone())),
                created: creation_date,
                ..Default::default()
            },
            &DIDKey,
            &mut ContextLoader::default(),
        )
        .await?;
    log::trace!("Proof preparation complete");

    Ok(proof_preparation)
}
