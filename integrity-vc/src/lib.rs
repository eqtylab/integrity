#[cfg(not(target_arch = "wasm32"))]
mod signer_adapter;

use anyhow::Result;
#[cfg(not(target_arch = "wasm32"))]
use anyhow::{anyhow, bail};
#[cfg(not(target_arch = "wasm32"))]
use chrono::{DateTime, Utc};
#[cfg(not(target_arch = "wasm32"))]
use integrity_signer::SignerType;
#[cfg(not(target_arch = "wasm32"))]
use serde_json::Value;
/// Re-export so callers (FFI, lineage-models, examples) don't depend on ssi
/// crate paths directly.
#[cfg(not(target_arch = "wasm32"))]
pub use ssi::claims::vc::v2::syntax::JsonCredential as Credential;
#[cfg(not(target_arch = "wasm32"))]
use ssi::{
    claims::{
        data_integrity::{AnySuite, CryptographicSuite, DataIntegrity, ProofOptions},
        vc::v2::syntax::JsonCredential,
        VerificationParameters,
    },
    dids::{AnyDidMethod, VerificationMethodDIDResolver},
    verification_methods::{AnyMethod, ProofPurpose},
};

#[cfg(not(target_arch = "wasm32"))]
use crate::signer_adapter::IntegritySigner;

/// A signed VC: a `JsonCredential` (W3C VC 2.0 syntax) bundled with one or
/// more Data-Integrity proofs from any supported cryptosuite.
#[cfg(not(target_arch = "wasm32"))]
pub type SignedVc = DataIntegrity<JsonCredential, AnySuite>;

/// Creates and signs a Verifiable Credential.
///
/// # Arguments
/// * `subject` - Credential subject. If it parses as a JSON object, used
///   directly; otherwise wrapped as `{"id": subject}`.
/// * `signer` - Signer for the credential. The issuer DID is derived from
///   `signer.get_did_doc().id`.
#[cfg(not(target_arch = "wasm32"))]
pub async fn issue_vc(subject: &str, signer: SignerType) -> Result<SignedVc> {
    log::debug!("Issuing VC for '{subject}'");
    let adapter = IntegritySigner::new(signer);
    let unsigned = build_unsigned(subject, &adapter)?;
    log::trace!("Unsigned VC: {}", serde_json::to_string_pretty(&unsigned)?);
    sign(unsigned, adapter).await
}

/// Creates and signs a revocable Verifiable Credential.
///
/// Builds an unsigned VC, posts it to the vc-status-server at
/// `status_server_url` to allocate status-list slots, then signs the
/// returned VC (which now carries `credentialStatus` entries) and returns
/// it as a typed `SignedVc`.
///
/// The server's response shape (multi-entry `credentialStatus`) is now
/// natively supported by `JsonCredential` v2.
#[cfg(not(target_arch = "wasm32"))]
pub async fn issue_revocable_vc(
    subject: &str,
    signer: SignerType,
    status_server_url: &str,
    status_server_jwt: &str,
) -> Result<SignedVc> {
    log::debug!("Issuing revocable VC for '{subject}' via {status_server_url}");

    let adapter = IntegritySigner::new(signer);
    let unsigned = build_unsigned(subject, &adapter)?;
    let unsigned_json = serde_json::to_string(&unsigned)?;
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

    let allocated: JsonCredential = serde_json::from_str(&body).map_err(|e| {
        anyhow!("failed to parse allocated VC as JsonCredential: {e}. Body: {body}")
    })?;

    sign(allocated, adapter).await
}

/// Signs an already-built unsigned `JsonCredential`.
#[cfg(not(target_arch = "wasm32"))]
pub async fn sign_vc(unsigned: JsonCredential, signer: SignerType) -> Result<SignedVc> {
    let adapter = IntegritySigner::new(signer);
    sign(unsigned, adapter).await
}

/// Verifies a signed VC's Data-Integrity proof.
///
/// Returns a human-readable summary on success. Currently only checks the
/// cryptographic proof; revocation-status checks (fetching status-list VCs
/// and reading the bit) are a separate concern.
#[cfg(not(target_arch = "wasm32"))]
pub async fn verify_vc(vc_json: &str) -> Result<String> {
    let vc: SignedVc = serde_json::from_str(vc_json)?;
    let resolver = VerificationMethodDIDResolver::<_, AnyMethod>::new(AnyDidMethod::default());
    let params = VerificationParameters::from_resolver(resolver);
    let outcome = vc
        .verify(params)
        .await
        .map_err(|e| anyhow!("verification error: {e}"))?;
    outcome.map_err(|e| anyhow!("invalid VC proof: {e:?}"))?;
    Ok("VC verification result: ok".to_string())
}

#[cfg(not(target_arch = "wasm32"))]
fn build_unsigned(subject: &str, adapter: &IntegritySigner) -> Result<JsonCredential> {
    use iref::UriBuf;
    use ssi::claims::vc::syntax::{IdOr, NonEmptyVec};

    // Subject can be either a JSON object or an opaque string (DID, URN, ...)
    // — match the polymorphism of the old API.
    let subject_value: serde_json::Map<String, Value> =
        if let Ok(Value::Object(obj)) = serde_json::from_str::<Value>(subject) {
            obj
        } else {
            let mut m = serde_json::Map::new();
            m.insert("id".to_string(), Value::String(subject.to_string()));
            m
        };
    let subject_json_syntax: json_syntax::Object = serde_json::from_value(Value::Object(
        subject_value,
    ))
    .map(|v: json_syntax::Value| match v {
        json_syntax::Value::Object(o) => o,
        _ => unreachable!("we just serialized from a Value::Object"),
    })?;
    let subject_non_empty = ssi::claims::vc::syntax::NonEmptyObject::try_from(subject_json_syntax)
        .map_err(|_| anyhow!("credential subject must be a non-empty object"))?;

    let id = UriBuf::new(format!("urn:uuid:{}", uuid::Uuid::new_v4()).into_bytes())
        .map_err(|e| anyhow!("failed to construct urn:uuid id: {e:?}"))?;

    let issuer = IdOr::Id(adapter.issuer_uri()?);

    // Backdate by 1 hour so VCs are valid immediately even across systems
    // with slight clock drift — same heuristic as the old code at
    // integrity-vc/src/lib.rs:113.
    let valid_from: DateTime<Utc> = Utc::now() - chrono::Duration::hours(1);
    let valid_from_xsd = xsd_types::DateTimeStamp::from(valid_from);

    let mut credential = JsonCredential::new(Some(id), issuer, NonEmptyVec::new(subject_non_empty));
    credential.valid_from = Some(valid_from_xsd.into());

    Ok(credential)
}

#[cfg(not(target_arch = "wasm32"))]
async fn sign(unsigned: JsonCredential, adapter: IntegritySigner) -> Result<SignedVc> {
    log::debug!("Signing VC");
    let suite = adapter.suite()?;
    let vm_iri = adapter.verification_method_iri()?;
    let resolver = VerificationMethodDIDResolver::<_, AnyMethod>::new(AnyDidMethod::default());

    // Match the same backdate-by-1-hour the credential uses for valid_from.
    let created: DateTime<Utc> = Utc::now() - chrono::Duration::hours(1);
    let created_xsd = xsd_types::DateTimeStamp::from(created);

    let proof_options = ProofOptions::new(
        created_xsd.into(),
        ssi::verification_methods::ReferenceOrOwned::Reference(vm_iri),
        ProofPurpose::Assertion,
        Default::default(),
    );

    suite
        .sign(unsigned, &resolver, &adapter, proof_options)
        .await
        .map_err(|e| anyhow!("signature failed: {e}"))
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use integrity_signer::{Ed25519Signer, SignerType};

    use super::*;

    #[tokio::test]
    async fn test_issue_vc_with_simple_subject() {
        let _ = env_logger::builder().is_test(true).try_init();

        let signer = Ed25519Signer::create().unwrap();
        let signer_type = SignerType::ED25519(signer);

        let subject = "urn:cid:bafkr4ibthuzk3zug7ghmx63yjqaiu6rx4hhfdv3453j5bodskgw57bx2ya";
        let signed = issue_vc(subject, signer_type).await.unwrap();

        assert!(
            !signed.proofs.is_empty(),
            "SignedVc should carry at least one proof"
        );

        let vc_json = serde_json::to_string(&signed).unwrap();
        assert!(vc_json.contains(subject), "Should reference subject");
    }

    #[tokio::test]
    async fn test_issue_vc_with_did_subject() {
        let _ = env_logger::builder().is_test(true).try_init();

        let signer = Ed25519Signer::create().unwrap();
        let signer_type = SignerType::ED25519(signer);

        let subject = "did:key:z6Mkw2PvzC9DHXiYQHMDRwyxCCV9n4EDc6vqqp1uyi9nrwsP";
        let signed = issue_vc(subject, signer_type).await.unwrap();
        assert!(!signed.proofs.is_empty());

        let vc_json = serde_json::to_string(&signed).unwrap();
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
        let signed = issue_vc(subject, signer_type).await.unwrap();

        let vc_json = serde_json::to_string(&signed).unwrap();
        let result = verify_vc(&vc_json).await;
        assert!(
            result.is_ok(),
            "Credential verification should succeed: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn test_issue_vc_with_json_subject() {
        let _ = env_logger::builder().is_test(true).try_init();

        let signer = Ed25519Signer::create().unwrap();
        let signer_type = SignerType::ED25519(signer);

        let subject = r#"{"id": "urn:cid:bafkr4ibthuzk3zug7ghmx63yjqaiu6rx4hhfdv3453j5bodskgw57bx2ya", "name": "Test Subject"}"#;
        let signed = issue_vc(subject, signer_type).await.unwrap();
        assert!(!signed.proofs.is_empty());

        let vc_json = serde_json::to_string(&signed).unwrap();
        assert!(vc_json.contains("Test Subject"));
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
        let signed = issue_revocable_vc(
            "did:key:z6Mkw2PvzC9DHXiYQHMDRwyxCCV9n4EDc6vqqp1uyi9nrwsP",
            signer_type,
            &server.uri(),
            "test-jwt",
        )
        .await
        .unwrap();

        assert!(!signed.proofs.is_empty(), "SignedVc should have a proof");

        // Multi-status is now native — typed access, no JSON munging.
        let statuses = &signed.claims.credential_status;
        assert_eq!(
            statuses.len(),
            2,
            "Both revocation and suspension entries preserved"
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
}
