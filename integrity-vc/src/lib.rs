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
use integrity_signer::SignerType;
#[cfg(not(target_arch = "wasm32"))]
use serde::ser::{Serialize, SerializeStruct, Serializer};
#[cfg(not(target_arch = "wasm32"))]
use serde_json::Value;
use ssi::{jsonld::ContextLoader, vc::Credential};
#[cfg(not(target_arch = "wasm32"))]
use ssi::{
    jsonld::{json_to_dataset, parse_ld_context, rdf::DataSet},
    jwk::JWK,
    ldp::{
        Error as LdpError, LinkedDataDocument, LinkedDataProofs, Proof, ProofPreparation,
        ProofSuite, ProofSuiteType, SigningInput,
    },
    one_or_many::OneOrMany,
    vc::{LinkedDataProofOptions, ProofPurpose, VCDateTime, URI},
};

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

/// Creates and signs a revocable Verifiable Credential.
///
/// Builds an unsigned VC, posts it to the vc-status-server at
/// `status_server_url` to allocate a status-list slot, then signs the
/// returned VC (which now carries `credentialStatus` entries) and returns
/// it as a JSON string.
///
/// # Arguments
///
/// * `subject` - The credential subject identifier (DID or other identifier).
/// * `signer` - The signer to use for signing the credential.
/// * `status_server_url` - Base URL of the VC status server (no path, with or
///   without trailing slash).
/// * `status_server_jwt` - Bearer JWT issued by the status server. Its `sub`
///   claim must match the VC's issuer (the signer's DID); otherwise the
///   server returns 403.
///
/// # Returns
///
/// The signed VC as a JSON string. A string is returned (rather than an
/// `ssi::vc::Credential`) because the status server appends multiple
/// `credentialStatus` entries (one per purpose), which ssi 0.7's
/// `Credential` struct cannot model — it expects a single object. The raw
/// JSON preserves the server response verbatim.
#[cfg(not(target_arch = "wasm32"))]
pub async fn issue_revocable_vc(
    subject: &str,
    signer: SignerType,
    status_server_url: &str,
    status_server_jwt: &str,
) -> Result<String> {
    log::debug!("Issuing revocable VC for '{subject}' via {status_server_url}");

    let did_doc = signer.get_did_doc();
    let vc = VerifiableCredential::from_did_doc(subject, &did_doc);
    let unsigned_vc: Credential = vc.try_into()?;
    let unsigned_json = serde_json::to_string(&unsigned_vc)?;
    log::trace!("Unsigned VC sent to status server: {unsigned_json}");

    let url = format!(
        "{}/credentials/status/allocate",
        status_server_url.trim_end_matches('/')
    );
    let resp = reqwest::Client::new()
        .post(&url)
        .bearer_auth(status_server_jwt)
        .header("Content-Type", "application/json")
        .body(unsigned_json)
        .send()
        .await?;

    let status = resp.status();
    let body = resp.text().await?;
    log::trace!("Status server response ({status}): {body}");

    if !status.is_success() {
        bail!("status server allocate failed ({status}): {body}");
    }

    let mut allocated: Value = serde_json::from_str(&body)
        .map_err(|e| anyhow!("failed to parse allocated VC body as JSON: {e}. Body: {body}"))?;

    // Server is supposed to strip pre-existing proofs, but be defensive so the
    // signature is always over the proof-less doc.
    if let Some(obj) = allocated.as_object_mut() {
        obj.remove("proof");
    }

    let proof_date = allocated
        .get("issuanceDate")
        .and_then(Value::as_str)
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&Utc))
        .or_else(|| Some(Utc::now() - chrono::Duration::hours(1)));

    let raw_doc = RawJsonVc {
        value: allocated.clone(),
    };
    let proof = sign_ld_doc(&raw_doc, signer, proof_date).await?;

    if let Some(obj) = allocated.as_object_mut() {
        obj.insert("proof".to_string(), serde_json::to_value(&proof)?);
    }

    Ok(serde_json::to_string(&allocated)?)
}

/// A `LinkedDataDocument` that wraps an arbitrary JSON-LD VC document.
///
/// Used to sign VCs whose shape (e.g. multi-entry `credentialStatus`) the
/// strongly-typed `ssi::vc::Credential` cannot represent.
#[cfg(not(target_arch = "wasm32"))]
struct RawJsonVc {
    value: Value,
}

#[cfg(not(target_arch = "wasm32"))]
#[async_trait::async_trait]
impl LinkedDataDocument for RawJsonVc {
    fn get_contexts(&self) -> Result<Option<String>, LdpError> {
        let ctx = self
            .value
            .get("@context")
            .cloned()
            .unwrap_or(serde_json::json!([]));
        Ok(Some(serde_json::to_string(&ctx)?))
    }

    async fn to_dataset_for_signing(
        &self,
        parent: Option<&(dyn LinkedDataDocument + Sync)>,
        context_loader: &mut ContextLoader,
    ) -> Result<DataSet, LdpError> {
        let mut copy = self.value.clone();
        if let Some(obj) = copy.as_object_mut() {
            obj.remove("proof");
        }
        let json = ssi::jsonld::syntax::to_value_with(copy, Default::default).unwrap();
        let parent_ctx = parent
            .map(LinkedDataDocument::get_contexts)
            .transpose()?
            .flatten()
            .as_deref()
            .map(parse_ld_context)
            .transpose()?;
        Ok(json_to_dataset(json, context_loader, parent_ctx).await?)
    }

    fn to_value(&self) -> Result<Value, LdpError> {
        Ok(self.value.clone())
    }

    fn get_issuer(&self) -> Option<&str> {
        self.value.get("issuer").and_then(Value::as_str)
    }

    fn get_default_proof_purpose(&self) -> Option<ProofPurpose> {
        Some(ProofPurpose::AssertionMethod)
    }
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
        Some(Utc::now() - chrono::Duration::hours(1))
    };

    let proof = sign_ld_doc(unsigned_vc, signer, proof_date).await?;

    let signed_vc = Credential {
        proof: Some(OneOrMany::One(proof)),
        ..unsigned_vc.clone()
    };

    Ok(signed_vc)
}

/// Generic JSON-LD document signing flow used by both `sign_vc` and
/// `issue_revocable_vc`.
///
/// Prepares a linked-data proof for the given document, hands the canonical
/// signing-input bytes to the signer, completes the proof with the resulting
/// signature, and returns the finished `Proof`. Callers attach it to their
/// own document representation.
#[cfg(not(target_arch = "wasm32"))]
async fn sign_ld_doc(
    doc: &(dyn LinkedDataDocument + Sync),
    signer: SignerType,
    proof_date: Option<DateTime<Utc>>,
) -> Result<Proof> {
    log::trace!("Getting DID Doc from signer");
    let did_doc = signer.get_did_doc();
    let proof_preparation = prepare_vc_proof(&did_doc, doc, proof_date).await?;

    let data = match &proof_preparation.signing_input {
        SigningInput::Bytes(bytes) => bytes.0.clone(),
        _ => bail!("Invalid signing input type. Expected bytes."),
    };

    let signature = signer.sign(&data).await?;
    let signature = BASE64_URL_NO_PAD.encode(signature);

    Ok(proof_preparation
        .proof
        .type_
        .complete(&proof_preparation, &signature)
        .await?)
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
    doc: &(dyn LinkedDataDocument + Sync),
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

    let proof_preparation = LinkedDataProofs::prepare(
        doc,
        &LinkedDataProofOptions {
            type_: Some(proof_type),
            proof_purpose: Some(ProofPurpose::AssertionMethod),
            verification_method: Some(URI::String(verification_method.id.clone())),
            created: creation_date,
            ..Default::default()
        },
        &DIDKey,
        &mut ContextLoader::default(),
        &jwk,
        None,
    )
    .await?;
    log::trace!("Proof preparation complete");

    Ok(proof_preparation)
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
        assert!(credential.proof.is_some(), "Credential should have a proof");
        assert!(
            credential.issuer.is_some(),
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

        assert!(credential.proof.is_some(), "Credential should have a proof");

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

        assert!(credential.proof.is_some(), "Credential should have a proof");

        // Verify the credential can be serialized
        let vc_json = serde_json::to_string(&credential);
        assert!(vc_json.is_ok(), "Credential should serialize to JSON");
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
    async fn test_issue_revocable_vc() {
        use wiremock::{
            matchers::{header, method, path},
            Mock, MockServer, Request, Respond, ResponseTemplate,
        };

        struct AllocateResponder;
        impl Respond for AllocateResponder {
            fn respond(&self, req: &Request) -> ResponseTemplate {
                let mut vc: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
                vc["credentialStatus"] = serde_json::json!([
                    {
                        "id": "https://status.example/status-lists/abc#42",
                        "type": "BitstringStatusListEntry",
                        "statusPurpose": "revocation",
                        "statusListIndex": "42",
                        "statusListCredential": "https://status.example/status-lists/abc"
                    },
                    {
                        "id": "https://status.example/status-lists/abc#43",
                        "type": "BitstringStatusListEntry",
                        "statusPurpose": "suspension",
                        "statusListIndex": "43",
                        "statusListCredential": "https://status.example/status-lists/abc"
                    }
                ]);
                ResponseTemplate::new(200).set_body_json(vc)
            }
        }

        let _ = env_logger::builder().is_test(true).try_init();
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/credentials/status/allocate"))
            .and(header("Authorization", "Bearer test-jwt"))
            .respond_with(AllocateResponder)
            .mount(&server)
            .await;

        let signer = Ed25519Signer::create().unwrap();
        let signer_type = SignerType::ED25519(signer);
        let vc_json = issue_revocable_vc(
            "did:key:z6Mkw2PvzC9DHXiYQHMDRwyxCCV9n4EDc6vqqp1uyi9nrwsP",
            signer_type,
            &server.uri(),
            "test-jwt",
        )
        .await
        .unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&vc_json).unwrap();
        assert!(
            parsed.get("proof").is_some(),
            "VC should have a proof: {vc_json}"
        );

        let status = parsed
            .get("credentialStatus")
            .and_then(|v| v.as_array())
            .expect("credentialStatus should be an array preserved from server response");
        assert_eq!(
            status.len(),
            2,
            "Both revocation and suspension entries preserved"
        );
        assert!(
            status
                .iter()
                .any(|e| e.get("statusPurpose").and_then(|v| v.as_str()) == Some("revocation")),
            "Should retain revocation entry"
        );
        assert!(
            status
                .iter()
                .any(|e| e.get("statusPurpose").and_then(|v| v.as_str()) == Some("suspension")),
            "Should retain suspension entry"
        );
    }

    #[tokio::test]
    async fn test_issue_revocable_vc_propagates_server_error() {
        use wiremock::{
            matchers::{method, path},
            Mock, MockServer, ResponseTemplate,
        };

        let _ = env_logger::builder().is_test(true).try_init();
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/credentials/status/allocate"))
            .respond_with(
                ResponseTemplate::new(403)
                    .set_body_string(r#"{"error":"forbidden","message":"sub mismatch"}"#),
            )
            .mount(&server)
            .await;

        let signer = Ed25519Signer::create().unwrap();
        let signer_type = SignerType::ED25519(signer);
        let err = issue_revocable_vc(
            "did:key:z6Mkw2PvzC9DHXiYQHMDRwyxCCV9n4EDc6vqqp1uyi9nrwsP",
            signer_type,
            &server.uri(),
            "test-jwt",
        )
        .await
        .unwrap_err();

        let msg = format!("{err}");
        assert!(msg.contains("403"), "error should mention status: {msg}");
        assert!(
            msg.contains("sub mismatch"),
            "error should include body: {msg}"
        );
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
