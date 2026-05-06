use core::default::Default;
#[cfg(not(target_arch = "wasm32"))]
use std::borrow::Cow;

#[cfg(not(target_arch = "wasm32"))]
use anyhow::anyhow;
use anyhow::Result;
#[cfg(not(target_arch = "wasm32"))]
use chrono::Utc;
#[cfg(not(target_arch = "wasm32"))]
use did_key::KeyFormat;
#[cfg(not(target_arch = "wasm32"))]
use integrity_signer::SignerType;
#[cfg(not(target_arch = "wasm32"))]
use serde::ser::{Serialize, SerializeStruct, Serializer};
#[cfg(not(target_arch = "wasm32"))]
use serde_json::Value;
use ssi::claims::{
    data_integrity::{
        AnyInputSuiteOptions, AnySuite, CryptographicSuite, DataIntegrity, ProofOptions,
    },
    vc::v1::{data_integrity::any_credential_from_json_str, JsonCredential},
    VerificationParameters,
};
#[cfg(not(target_arch = "wasm32"))]
use ssi::verification_methods::ProofPurpose;
#[cfg(not(target_arch = "wasm32"))]
use ssi::xsd::DateTimeStamp;
#[cfg(not(target_arch = "wasm32"))]
use ssi::{
    dids::{DIDResolver, VerificationMethodDIDResolver},
    verification_methods::{AnyMethod, MessageSigner, ReferenceOrOwned, Signer},
};

pub type UnsignedCredential = JsonCredential;
pub type Credential = DataIntegrity<JsonCredential, AnySuite>;

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
    pub expiration_date: Option<String>,
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
        let unsigned_vc: UnsignedCredential = serde_json::from_str(&vc_str)?;
        Ok(DataIntegrity::new(unsigned_vc, Default::default()))
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl TryInto<UnsignedCredential> for VerifiableCredential {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<UnsignedCredential> {
        let vc_str = serde_json::to_string(&self)?;
        Ok(serde_json::from_str(&vc_str)?)
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
pub async fn sign_vc(unsigned_vc: &UnsignedCredential, signer: SignerType) -> Result<Credential> {
    log::debug!("Signing VC with {signer:?}");
    let (resolver, verification_method) = resolve_verification_method(&signer).await?;
    let options = prepare_proof_options(unsigned_vc, verification_method);
    let signer = IntegritySigner::new(signer);
    let jwk = signer.public_jwk()?;
    let suite = AnySuite::pick(&jwk, options.verification_method.as_ref())
        .ok_or_else(|| anyhow!("failed to pick cryptographic suite"))?;

    suite
        .sign(unsigned_vc.clone(), &resolver, &signer, options)
        .await
        .map_err(Into::into)
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
    let vc = any_credential_from_json_str(vc)?;
    let resolver = did_method_key::DIDKey.into_vm_resolver::<AnyMethod>();
    let params = VerificationParameters::from_resolver(resolver);
    let result = vc.verify(params).await?;

    if let Err(err) = &result {
        return Err(anyhow!("VC verification failed: {err}"));
    }

    Ok("VC verification result:\nvalid".to_owned())
}

#[cfg(not(target_arch = "wasm32"))]
async fn resolve_verification_method(
    signer: &SignerType,
) -> Result<(
    VerificationMethodDIDResolver<did_method_key::DIDKey, AnyMethod>,
    ReferenceOrOwned<AnyMethod>,
)> {
    let did_doc = signer.get_did_doc();
    let verification_method = did_doc
        .verification_method
        .first()
        .ok_or_else(|| anyhow!("verification method not found in DID document"))?;
    let verification_method = ReferenceOrOwned::Reference(verification_method.id.parse()?);
    let resolver = did_method_key::DIDKey.into_vm_resolver::<AnyMethod>();
    Ok((resolver, verification_method))
}

#[cfg(not(target_arch = "wasm32"))]
fn prepare_proof_options(
    unsigned_vc: &UnsignedCredential,
    verification_method: ReferenceOrOwned<AnyMethod>,
) -> ProofOptions<AnyMethod, AnyInputSuiteOptions> {
    let created = unsigned_vc
        .issuance_date
        .as_ref()
        .and_then(|date| chrono::DateTime::parse_from_rfc3339(&date.to_string()).ok())
        .map(|date| date.with_timezone(&Utc))
        .unwrap_or_else(|| Utc::now() - chrono::Duration::hours(1));

    ProofOptions {
        created: Some(DateTimeStamp::from(created).into()),
        verification_method: Some(verification_method),
        proof_purpose: ProofPurpose::Assertion,
        ..Default::default()
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Clone)]
struct IntegritySigner {
    signer: SignerType,
}

#[cfg(not(target_arch = "wasm32"))]
impl IntegritySigner {
    fn new(signer: SignerType) -> Self {
        Self { signer }
    }

    fn public_jwk(&self) -> Result<ssi::jwk::JWK> {
        let did_doc = self.signer.get_did_doc();
        let verification_method = did_doc
            .verification_method
            .first()
            .ok_or_else(|| anyhow!("verification method not found in DID document"))?;

        match &verification_method.public_key {
            Some(KeyFormat::JWK(jwk)) => {
                let jwk_json = serde_json::to_value(jwk)?;
                Ok(serde_json::from_value::<ssi::jwk::JWK>(jwk_json)?)
            }
            _ => Err(anyhow!(
                "public key not found or not in JWK format in DID verification method"
            )),
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl Signer<AnyMethod> for IntegritySigner {
    type MessageSigner = Self;

    async fn for_method(
        &self,
        _method: Cow<'_, AnyMethod>,
    ) -> Result<Option<Self::MessageSigner>, ssi::claims::SignatureError> {
        Ok(Some(self.clone()))
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl<A> MessageSigner<A> for IntegritySigner
where
    A: ssi::crypto::algorithm::SignatureAlgorithmType,
{
    async fn sign(
        self,
        _algorithm: A::Instance,
        message: &[u8],
    ) -> Result<Vec<u8>, ssi::claims::MessageSignatureError> {
        self.signer
            .sign(message)
            .await
            .map(|signature| signature.to_vec())
            .map_err(ssi::claims::MessageSignatureError::signature_failed)
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use integrity_signer::{Ed25519Signer, SignerType};

    use super::*;

    #[tokio::test]
    async fn test_issue_vc_with_simple_subject() {
        let _ = env_logger::builder().is_test(true).try_init();

        // Create an Ed25519 signer for testing
        let signer = Ed25519Signer::create().unwrap();
        let signer_type = SignerType::ED25519(signer);

        // Issue a VC with a simple subject identifier
        let subject = "urn:cid:bafkr4ibthuzk3zug7ghmx63yjqaiu6rx4hhfdv3453j5bodskgw57bx2ya";
        let credential = issue_vc(subject, signer_type).await.unwrap();

        // Verify the credential has expected structure
        assert!(
            !credential.proofs.is_empty(),
            "Credential should have a proof"
        );
        assert!(
            !credential.issuer.id().as_str().is_empty(),
            "Credential should have an issuer"
        );

        // Verify the credential can be serialized to JSON
        let vc_json = serde_json::to_string(&credential);
        assert!(vc_json.is_ok(), "Credential should serialize to JSON");
    }

    #[tokio::test]
    async fn test_issue_vc_with_did_subject() {
        let _ = env_logger::builder().is_test(true).try_init();

        let signer = Ed25519Signer::create().unwrap();
        let signer_type = SignerType::ED25519(signer);

        // Issue a VC with a DID as subject
        let subject = "did:key:z6Mkw2PvzC9DHXiYQHMDRwyxCCV9n4EDc6vqqp1uyi9nrwsP";
        let credential = issue_vc(subject, signer_type).await.unwrap();

        assert!(
            !credential.proofs.is_empty(),
            "Credential should have a proof"
        );

        // Verify the credential subject contains the DID
        let vc_json = serde_json::to_string(&credential).unwrap();
        assert!(
            vc_json.contains(subject),
            "Credential should contain the subject DID"
        );
    }

    #[tokio::test]
    async fn test_issue_and_verify_vc() {
        let _ = env_logger::builder().is_test(true).try_init();

        let signer = Ed25519Signer::create().unwrap();
        let signer_type = SignerType::ED25519(signer);

        let subject = "urn:cid:bafkr4ibthuzk3zug7ghmx63yjqaiu6rx4hhfdv3453j5bodskgw57bx2ya";
        let credential = issue_vc(subject, signer_type).await.unwrap();

        // Serialize the credential and verify it
        let vc_json = serde_json::to_string(&credential).unwrap();
        let verification_result = verify_vc(&vc_json).await;

        assert!(
            verification_result.is_ok(),
            "Credential verification should succeed: {:?}",
            verification_result.err()
        );
    }

    #[tokio::test]
    async fn test_issue_vc_with_json_subject() {
        let _ = env_logger::builder().is_test(true).try_init();

        let signer = Ed25519Signer::create().unwrap();
        let signer_type = SignerType::ED25519(signer);

        // Issue a VC with a JSON object as subject
        let subject = r#"{"id": "urn:cid:bafkr4ibthuzk3zug7ghmx63yjqaiu6rx4hhfdv3453j5bodskgw57bx2ya", "name": "Test Subject"}"#;
        let credential = issue_vc(subject, signer_type).await.unwrap();

        assert!(
            !credential.proofs.is_empty(),
            "Credential should have a proof"
        );

        // Verify the credential can be serialized
        let vc_json = serde_json::to_string(&credential);
        assert!(vc_json.is_ok(), "Credential should serialize to JSON");
    }

    #[tokio::test]
    async fn test_sign_vc_from_unsigned_json() {
        let _ = env_logger::builder().is_test(true).try_init();

        let signer = Ed25519Signer::create().unwrap();
        let signer_type = SignerType::ED25519(signer);

        let unsigned_vc = serde_json::json!({
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://w3id.org/security/v2"
            ],
            "type": ["VerifiableCredential"],
            "id": "urn:uuid:12345678-1234-1234-1234-123456789012",
            "issuer": "did:key:z6Mkw2PvzC9DHXiYQHMDRwyxCCV9n4EDc6vqqp1uyi9nrwsP",
            "issuanceDate": "2024-01-01T00:00:00Z",
            "validFrom": "2024-01-01T00:00:00Z",
            "credentialSubject": {
                "id": "urn:cid:bafkr4ibthuzk3zug7ghmx63yjqaiu6rx4hhfdv3453j5bodskgw57bx2ya"
            }
        });

        let unsigned_vc: UnsignedCredential = serde_json::from_value(unsigned_vc).unwrap();

        let signed = sign_vc(&unsigned_vc, signer_type).await.unwrap();

        assert!(
            !signed.proofs.is_empty(),
            "Signed credential should have a proof"
        );

        let vc_json = serde_json::to_string(&signed).unwrap();
        let verification_result = verify_vc(&vc_json).await;
        assert!(
            verification_result.is_ok(),
            "Signed credential should verify: {:?}",
            verification_result.err()
        );
    }

    #[tokio::test]
    async fn test_verifiable_credential_serialization() {
        let _ = env_logger::builder().is_test(true).try_init();

        let signer = Ed25519Signer::create().unwrap();
        let did_doc = signer.did_doc.clone();

        let vc = VerifiableCredential::from_did_doc(
            "urn:cid:bafkr4ibthuzk3zug7ghmx63yjqaiu6rx4hhfdv3453j5bodskgw57bx2ya",
            &did_doc,
        );

        // Serialize to JSON
        let vc_json = serde_json::to_string(&vc).unwrap();

        // Verify expected fields are present
        assert!(vc_json.contains("@context"), "Should have @context");
        assert!(
            vc_json.contains("https://www.w3.org/ns/credentials/v2"),
            "Should have W3C VC context"
        );
        assert!(
            vc_json.contains("VerifiableCredential"),
            "Should have VerifiableCredential type"
        );
        assert!(
            vc_json.contains("credentialSubject"),
            "Should have credentialSubject"
        );
        assert!(vc_json.contains("issuer"), "Should have issuer");
        assert!(vc_json.contains("issuanceDate"), "Should have issuanceDate");
    }

    #[tokio::test]
    async fn test_verifiable_credential_try_into_credential() {
        let _ = env_logger::builder().is_test(true).try_init();

        let signer = Ed25519Signer::create().unwrap();
        let did_doc = signer.did_doc.clone();

        let vc = VerifiableCredential::from_did_doc(
            "urn:cid:bafkr4ibthuzk3zug7ghmx63yjqaiu6rx4hhfdv3453j5bodskgw57bx2ya",
            &did_doc,
        );

        // Convert to SSI Credential - this exercises the JSON-LD parsing path
        let credential: Result<Credential> = vc.try_into();
        assert!(
            credential.is_ok(),
            "VerifiableCredential should convert to Credential: {:?}",
            credential.err()
        );
    }
}
