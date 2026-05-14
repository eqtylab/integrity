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
    if is_legacy_vc(vc_json) {
        return verify_legacy_vc(vc_json).await;
    }

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

/// Detect a legacy VC: a JSON document whose top-level `@context` references
/// the W3C VC 2.0 base context AND whose top-level fields include
/// `issuanceDate` (a v1-only field that v2 doesn't define). Together these
/// uniquely identify pre-ssi-0.16 output from this repo, which used a
/// hybrid v1/v2 shape that ssi 0.16's strict JSON-LD pipeline can't
/// reproduce the canonical bytes for.
#[cfg(not(target_arch = "wasm32"))]
fn is_legacy_vc(vc_json: &str) -> bool {
    let v: Value = match serde_json::from_str(vc_json) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let has_issuance_date = v.get("issuanceDate").is_some();
    let v2_context = v
        .get("@context")
        .and_then(|c| c.as_array())
        .map(|arr| {
            arr.iter()
                .any(|e| e.as_str() == Some("https://www.w3.org/ns/credentials/v2"))
        })
        .unwrap_or(false);
    has_issuance_date && v2_context
}

/// Verifies a legacy (pre-ssi-0.16) VC by dispatching to ssi 0.7, which is
/// kept around as an aliased `ssi-legacy` dep specifically for this case.
///
/// Uses a custom JSON-LD context loader (`LegacyV2Loader`) that overrides
/// `credentials/v2` with the ssi-contexts 0.1.5 content (the version ssi
/// 0.7 originally depended on) and delegates everything else to the
/// standard ssi-json-ld static loader. 0.1.5's `credentials/v2` includes a
/// top-level `@vocab: "https://www.w3.org/ns/credentials/issuer-dependent#"`
/// fallback that ssi-contexts 0.1.10 dropped — that fallback is what made
/// `issuanceDate` and undefined evidence types expand to fallback IRIs
/// (instead of erroring) during the original signing canonicalization.
/// Cargo unifies ssi-contexts to 0.1.10 in our build because ssi 0.16's
/// chain requires `>=0.1.10`, so we can't pin downward — but we CAN feed
/// 0.1.5's content directly to the loader for the legacy path only.
#[cfg(not(target_arch = "wasm32"))]
async fn verify_legacy_vc(vc_json: &str) -> Result<String> {
    use did_method_key_legacy::DIDKey;
    use ssi_legacy::vc::Credential;

    let vc = Credential::from_json_unsigned(vc_json)
        .map_err(|e| anyhow!("failed to parse legacy VC: {e}"))?;

    let mut loader = ssi_legacy::jsonld::ContextLoader::empty()
        .with_context_map_from(legacy_context_overrides())
        .map_err(|e| anyhow!("failed to build legacy context loader: {e}"))?;
    let result = vc.verify(None, &DIDKey, &mut loader).await;
    log::debug!(
        "legacy verify errors={:?} warnings={:?} checks={:?}",
        result.errors,
        result.warnings,
        result.checks
    );
    if !result.errors.is_empty() {
        bail!("legacy VC verification failed: {:?}", result.errors);
    }
    Ok("VC verification result: ok (legacy path)".to_string())
}

/// Bundled W3C contexts at the ssi-contexts 0.1.5 revision — the version
/// shipped with ssi 0.7 originally. We override the same URLs the static
/// loader would resolve so that legacy verification sees the older context
/// shape (notably `credentials/v2` with its `@vocab` fallback that lets
/// custom evidence terms expand to predictable `issuer-dependent#` IRIs).
#[cfg(not(target_arch = "wasm32"))]
fn legacy_context_overrides() -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    map.insert(
        "https://www.w3.org/ns/credentials/v2".to_string(),
        include_str!("legacy_contexts/credentials-v2.jsonld").to_string(),
    );
    map.insert(
        "https://w3id.org/security/v2".to_string(),
        include_str!("legacy_contexts/security-v2.jsonld").to_string(),
    );
    map.insert(
        "https://w3id.org/security/v1".to_string(),
        include_str!("legacy_contexts/security-v1.jsonld").to_string(),
    );
    map
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

    // The v1-era proof suites (Ed25519Signature2018, EcdsaSecp256r1Signature2019,
    // EcdsaSecp256k1Signature2019) define their proof terms in
    // `https://w3id.org/security/v2` — without it, JSON-LD expansion of the
    // proof's `@type` fails. Adding the context here keeps both the v2 credential
    // body and the v1-era proof spec-coherent.
    credential
        .context
        .insert(ssi::json_ld::syntax::ContextEntry::IriRef(
            iref::IriRefBuf::new("https://w3id.org/security/v2".to_string())
                .map_err(|e| anyhow!("invalid security/v2 IRI: {e:?}"))?,
        ));

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

    /// Captured from running `test_issue_and_verify_vc` on commit 82f0f2e
    /// (last pre-ssi-0.16 commit). The OLD code's verify_vc successfully
    /// verified this exact JSON. If our `ssi-legacy` aliased dep behaves
    /// the same as the OLD code's ssi 0.7 dep, this should also verify.
    #[tokio::test]
    async fn test_verify_captured_old_vc() {
        let _ = env_logger::builder().is_test(true).try_init();

        let captured = r#"{"@context":["https://www.w3.org/ns/credentials/v2","https://w3id.org/security/v2"],"id":"urn:uuid:cf35933b-b49d-4b18-82ee-0e594912ec87","type":["VerifiableCredential"],"credentialSubject":{"id":"urn:cid:bafkr4ibthuzk3zug7ghmx63yjqaiu6rx4hhfdv3453j5bodskgw57bx2ya"},"issuer":"did:key:z6Mkt1QV8soXyenn4uUYtrMzFDnWWq8e8Mu71t2KmBsWi2mv","issuanceDate":"2026-05-14T13:43:44Z","proof":{"type":"Ed25519Signature2018","proofPurpose":"assertionMethod","verificationMethod":"did:key:z6Mkt1QV8soXyenn4uUYtrMzFDnWWq8e8Mu71t2KmBsWi2mv#z6Mkt1QV8soXyenn4uUYtrMzFDnWWq8e8Mu71t2KmBsWi2mv","created":"2026-05-14T13:43:44Z","jws":"eyJhbGciOiJFZERTQSIsImNyaXQiOlsiYjY0Il0sImI2NCI6ZmFsc2V9..P1CYP_-UNuPSyJUfE3EfLnHDZxHE1rZt961j1UQ6wx0f4ftTs3cUNmQ6pINp6VECGscjWnmvYtt4r2jt1-0YDg"},"validFrom":"2026-05-14T13:43:44Z"}"#;

        assert!(is_legacy_vc(captured), "should detect as legacy");
        let result = verify_vc(captured).await;
        assert!(
            result.is_ok(),
            "captured OLD-issued VC should verify via legacy path: {:?}",
            result.err()
        );
    }

    /// User-supplied legacy fixture with a custom `evidence` type. The
    /// `EqtyVCompCustomV1Evidence` term and `customType`/`report` properties
    /// aren't defined in any context the VC explicitly references — they
    /// rely on ssi-contexts 0.1.5's `@vocab` fallback in `credentials/v2`
    /// (`https://www.w3.org/ns/credentials/issuer-dependent#`) to expand
    /// to predictable IRIs during canonicalization. The legacy verifier
    /// feeds the 0.1.5 `credentials/v2` content to its loader directly via
    /// [`legacy_context_overrides`], so the canonical bytes match what the
    /// original signer hashed.
    #[tokio::test]
    async fn test_verify_legacy_vc() {
        let _ = env_logger::builder().is_test(true).try_init();

        let legacy_vc = r#"{
          "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://w3id.org/security/v2"
          ],
          "id": "urn:uuid:9c759cce-6433-4679-a293-9f77158a831a",
          "type": ["VerifiableCredential"],
          "credentialSubject": {
            "id": "urn:cid:bagb6qaq6edsd23d466wxytmkkdjqjfagkccwhtgetbfrkyqql3xdmgepe5s5k"
          },
          "issuer": "did:key:zDnaexxwdJ1key82YfVudPYvDqcKMhvcyYdTV7WDhATqbVtVc",
          "issuanceDate": "2026-04-30T15:51:28Z",
          "proof": {
            "type": "EcdsaSecp256r1Signature2019",
            "proofPurpose": "assertionMethod",
            "verificationMethod": "did:key:zDnaexxwdJ1key82YfVudPYvDqcKMhvcyYdTV7WDhATqbVtVc#zDnaexxwdJ1key82YfVudPYvDqcKMhvcyYdTV7WDhATqbVtVc",
            "created": "2026-04-30T15:51:28Z",
            "jws": "eyJhbGciOiJFUzI1NiIsImNyaXQiOlsiYjY0Il0sImI2NCI6ZmFsc2V9..fv7jObmZYGuX6tScXOmP-umY15zn4-9zjCpLnfVP4AAln00_p7t0j1CQYrQKMcPRD2e6Z0aS6WDRDnAg9790rg"
          },
          "evidence": {
            "type": ["EqtyVCompCustomV1Evidence"],
            "value": {
              "customType": "eqty-vcomp-amd-sev-v1",
              "report": "urn:cid:bafkr4iaosvuo7es74abc4wmwmwyui6xtbmgzxhway26y262a54kjhnzaze"
            }
          },
          "validFrom": "2026-04-30T15:51:28Z"
        }"#;

        let result = verify_vc(legacy_vc).await;
        assert!(
            result.is_ok(),
            "legacy VC verification should succeed: {:?}",
            result.err()
        );
    }

    /// Second user-supplied legacy fixture: Ed25519-signed, no evidence,
    /// minimal v2-with-issuanceDate shape. Confirms the legacy path also
    /// handles the simpler proof-suite-without-evidence variant.
    #[tokio::test]
    async fn test_verify_legacy_vc_ed25519_no_evidence() {
        let _ = env_logger::builder().is_test(true).try_init();

        let legacy_vc = r#"{
          "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://w3id.org/security/v2"
          ],
          "id": "urn:uuid:a77f4f8f-0ab1-4611-bd51-6090ebdefc8d",
          "type": ["VerifiableCredential"],
          "credentialSubject": {
            "id": "urn:cid:bagb6qaq6edqk2q2vksxblheqmhcfp6lfmwk5f6qqy7fkuzykaebfzyccfmsh4"
          },
          "issuer": "did:key:z6MkmwihXQDhgNbWpwpWZ5NHygqC9PtHjVW62MM8ZJSggRD4",
          "issuanceDate": "2025-05-22T16:25:37Z",
          "proof": {
            "type": "Ed25519Signature2018",
            "proofPurpose": "assertionMethod",
            "verificationMethod": "did:key:z6MkmwihXQDhgNbWpwpWZ5NHygqC9PtHjVW62MM8ZJSggRD4#z6MkmwihXQDhgNbWpwpWZ5NHygqC9PtHjVW62MM8ZJSggRD4",
            "created": "2025-05-22T16:25:37Z",
            "jws": "eyJhbGciOiJFZERTQSIsImNyaXQiOlsiYjY0Il0sImI2NCI6ZmFsc2V9..gHHpLIaNbMKQFHoyaOQEGu_HLgLwnwgBNSc6yRaWjoOBLGBj7x_FrX7nTBaiWcl_tcd9D-ir8QtFUh8n29WLAw"
          },
          "validFrom": "2025-05-22T16:25:37Z"
        }"#;

        let result = verify_vc(legacy_vc).await;
        assert!(
            result.is_ok(),
            "legacy VC verification should succeed: {:?}",
            result.err()
        );
    }
}
