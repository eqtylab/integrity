#![cfg(all(feature = "signer-auth-service", feature = "signer-p256"))]

use std::time::Duration;

use integrity_signer::{
    AuthServiceSigner, AuthSigningPurpose, BoundAuthServiceSigner, P256Signer, Signer, SignerType,
};
use p256::ecdsa::{
    signature::{hazmat::PrehashSigner, Verifier},
    Signature, SigningKey,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use wiremock::{
    matchers::{header, method, path},
    Mock, MockServer, Request, ResponseTemplate,
};

const REFERENCE: &str = "opaque owner/purpose/version reference";
const SECRET: [u8; 32] = [7; 32];
const MESSAGE: &[u8] = b"proof input is hashed exactly once";

fn metadata(purpose: AuthSigningPurpose) -> Value {
    json!({
        "signingKeyReference": REFERENCE,
        "algorithm": "p256", "joseAlgorithm": "ES256",
        "purpose": purpose, "hashAlgorithm": "SHA-256",
        "signatureEncoding": "ieee-p1363",
        "didDocument": P256Signer::import(&SECRET).unwrap().did_doc,
    })
}

fn signature_response(request: &Request) -> ResponseTemplate {
    let body: Value = serde_json::from_slice(&request.body).unwrap();
    assert_eq!(body["dataHash"], hex::encode(Sha256::digest(MESSAGE)));
    assert_eq!(body["signingKeyReference"], REFERENCE);
    let digest = hex::decode(body["dataHash"].as_str().unwrap()).unwrap();
    let key = SigningKey::from_bytes((&SECRET).into()).unwrap();
    let signature: Signature = key.sign_prehash(&digest).unwrap();
    ResponseTemplate::new(200).set_body_json(json!({
        "signature": hex::encode(signature.to_bytes()),
        "signingKeyReference": REFERENCE,
    }))
}

async fn mount_metadata(server: &MockServer, purpose: AuthSigningPurpose, value: Value) {
    let route = if purpose == AuthSigningPurpose::Platform {
        "platform/"
    } else {
        ""
    };
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/protected/{route}signing-key")))
        .respond_with(ResponseTemplate::new(200).set_body_json(value))
        .expect(1)
        .mount(server)
        .await;
}

async fn signer(server: &MockServer) -> BoundAuthServiceSigner {
    mount_metadata(
        server,
        AuthSigningPurpose::Did,
        metadata(AuthSigningPurpose::Did),
    )
    .await;
    BoundAuthServiceSigner::create("token".into(), server.uri(), AuthSigningPurpose::Did)
        .await
        .unwrap()
}

#[tokio::test]
async fn bound_user_service_account_and_platform_preserve_digest_and_reference() {
    for (token, purpose, route) in [
        ("user-token", AuthSigningPurpose::Did, ""),
        ("service-account-token", AuthSigningPurpose::Did, ""),
        ("owner-token", AuthSigningPurpose::Platform, "platform/"),
    ] {
        let server = MockServer::start().await;
        mount_metadata(&server, purpose, metadata(purpose)).await;
        Mock::given(method("POST"))
            .and(path(format!("/api/v1/protected/{route}sign")))
            .and(header("authorization", format!("Bearer {token}")))
            .respond_with(signature_response)
            .expect(1)
            .mount(&server)
            .await;
        let signer =
            BoundAuthServiceSigner::create(token.into(), format!("{}/", server.uri()), purpose)
                .await
                .unwrap();
        let did = signer.did_document().id.clone();
        let signer = SignerType::BoundAuthService(signer);
        let signature = signer.sign(MESSAGE).await.unwrap();
        let key = SigningKey::from_bytes((&SECRET).into()).unwrap();
        key.verifying_key()
            .verify(MESSAGE, &Signature::from_slice(&signature).unwrap())
            .unwrap();
        assert!(key
            .verifying_key()
            .verify(b"tampered", &Signature::from_slice(&signature).unwrap())
            .is_err());
        assert_eq!(signer.get_did_doc().id, did);
    }
}

#[tokio::test]
async fn legacy_client_accepts_new_server_without_binding() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/protected/did-doc"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(metadata(AuthSigningPurpose::Did)["didDocument"].clone()),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v1/protected/sign"))
        .respond_with(|req: &Request| {
            let body: Value = serde_json::from_slice(&req.body).unwrap();
            assert_eq!(
                body,
                json!({"dataHash": hex::encode(Sha256::digest(MESSAGE))})
            );
            ResponseTemplate::new(200).set_body_json(json!({"signature": "12".repeat(64)}))
        })
        .expect(1)
        .mount(&server)
        .await;
    let signer = AuthServiceSigner::create("token".into(), server.uri())
        .await
        .unwrap();
    let old_config = serde_json::to_value(&signer).unwrap();
    assert_eq!(old_config.as_object().unwrap().len(), 3);
    let loaded: AuthServiceSigner = serde_json::from_value(old_config).unwrap();
    assert_eq!(loaded.sign(MESSAGE).await.unwrap(), [0x12; 64]);
}

#[tokio::test]
async fn incompatible_metadata_never_falls_back() {
    for status in [404, 501, 503, 302] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/protected/signing-key"))
            .respond_with(
                ResponseTemplate::new(status)
                    .insert_header("Location", "/api/v1/protected/did-doc"),
            )
            .expect(1)
            .mount(&server)
            .await;
        assert!(BoundAuthServiceSigner::create(
            "token".into(),
            server.uri(),
            AuthSigningPurpose::Did
        )
        .await
        .is_err());
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }
    for (field, value) in [
        ("signingKeyReference", Value::Null),
        ("signingKeyReference", json!("")),
        ("purpose", json!("platform-did")),
        ("hashAlgorithm", json!("SHA-512")),
        ("algorithm", json!("ed25519")),
        ("joseAlgorithm", json!("ES256K")),
        ("signatureEncoding", json!("der")),
        ("didDocument", json!({})),
    ] {
        let server = MockServer::start().await;
        let mut value_metadata = metadata(AuthSigningPurpose::Did);
        value_metadata[field] = value;
        mount_metadata(&server, AuthSigningPurpose::Did, value_metadata).await;
        assert!(BoundAuthServiceSigner::create(
            "token".into(),
            server.uri(),
            AuthSigningPurpose::Did
        )
        .await
        .is_err());
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }
}

#[tokio::test]
async fn missing_mismatched_or_malformed_sign_responses_fail_closed() {
    for body in [
        json!({"signature": "12".repeat(64)}),
        json!({"signature": "12".repeat(64), "signingKeyReference": null}),
        json!({"signature": "12".repeat(64), "signingKeyReference": "other-version"}),
        json!({"signature": "12".repeat(63), "signingKeyReference": REFERENCE}),
        json!({"signature": "zz".repeat(64), "signingKeyReference": REFERENCE}),
    ] {
        let server = MockServer::start().await;
        let signer = signer(&server).await;
        Mock::given(method("POST"))
            .and(path("/api/v1/protected/sign"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .expect(1)
            .mount(&server)
            .await;
        assert!(signer.sign(MESSAGE).await.is_err());
        assert_eq!(signer.signing_key_reference(), REFERENCE);
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
    }
}

#[tokio::test]
async fn rotation_owner_purpose_conflicts_and_backend_failures_do_not_refresh_or_retry() {
    // Auth enforces ownership/purpose/version. Model its rejection; the real
    // Auth integration suite covers how each conflict is derived.
    for status in [409, 403, 404, 501, 503] {
        let server = MockServer::start().await;
        let signer = signer(&server).await;
        Mock::given(method("POST"))
            .and(path("/api/v1/protected/sign"))
            .respond_with(ResponseTemplate::new(status))
            .expect(2)
            .mount(&server)
            .await;
        for _ in 0..2 {
            assert!(signer.sign(MESSAGE).await.is_err());
        }
        assert_eq!(signer.signing_key_reference(), REFERENCE);
        assert_eq!(server.received_requests().await.unwrap().len(), 3);
    }
}

#[tokio::test]
async fn concurrent_clones_and_saved_config_keep_the_original_snapshot() {
    let server = MockServer::start().await;
    let signer = signer(&server).await;
    Mock::given(method("POST"))
        .and(path("/api/v1/protected/sign"))
        .respond_with(signature_response)
        .expect(12)
        .mount(&server)
        .await;
    let saved = serde_json::to_value(SignerType::BoundAuthService(signer)).unwrap();
    let mut tasks = Vec::new();
    for _ in 0..12 {
        let restored: SignerType = serde_json::from_value(saved.clone()).unwrap();
        tasks.push(tokio::spawn(async move {
            restored.sign(MESSAGE).await.unwrap()
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
    let mut broken = saved;
    broken["BoundAuthService"]["metadata"]
        .as_object_mut()
        .unwrap()
        .remove("signingKeyReference");
    assert!(serde_json::from_value::<SignerType>(broken).is_err());
    assert_eq!(server.received_requests().await.unwrap().len(), 13);
}

#[tokio::test]
async fn timeout_and_cancellation_do_not_replay_or_change_identity() {
    let server = MockServer::start().await;
    mount_metadata(
        &server,
        AuthSigningPurpose::Did,
        metadata(AuthSigningPurpose::Did),
    )
    .await;
    let signer = BoundAuthServiceSigner::create_with_timeout(
        "token".into(),
        server.uri(),
        AuthSigningPurpose::Did,
        Duration::from_millis(100),
    )
    .await
    .unwrap();
    Mock::given(method("POST"))
        .and(path("/api/v1/protected/sign"))
        .respond_with(ResponseTemplate::new(503).set_delay(Duration::from_secs(2)))
        .expect(2)
        .mount(&server)
        .await;
    let start = std::time::Instant::now();
    assert!(signer.sign(MESSAGE).await.is_err());
    assert!(start.elapsed() < Duration::from_secs(1));
    assert!(
        tokio::time::timeout(Duration::from_millis(50), signer.sign(MESSAGE))
            .await
            .is_err()
    );
    assert_eq!(signer.signing_key_reference(), REFERENCE);
    assert_eq!(server.received_requests().await.unwrap().len(), 3);
}
