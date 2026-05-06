use anyhow::Result;
use integrity_jsonld::ig_common_context_link;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use ssi::vc::{Credential, StringOrURI};

use super::{compute_cid, format_timestamp, get_jsonld_filename, StatementTrait};

/// Records a W3C Verifiable Credential
///
/// This statement type stores verifiable credentials in W3C VC format,
/// providing cryptographically verifiable claims about subjects.
#[derive(Clone, Debug, Serialize, Deserialize, utoipa::ToSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VcStatement {
    /// JSON-LD context URL
    #[serde(rename = "@context")]
    pub context: String,
    /// Unique identifier for this statement
    #[serde(rename = "@id")]
    id: String,
    /// Statement type identifier
    #[serde(rename = "@type")]
    pub type_: String,
    /// The W3C Verifiable Credential
    #[schema(value_type = Value)]
    pub credential: Credential,
    /// DID of the entity that registered this statement
    pub registered_by: String,
    /// ISO 8601 timestamp of when the statement was created
    pub timestamp: String,
}

impl StatementTrait for VcStatement {
    fn get_id(&self) -> String {
        self.id.clone()
    }

    fn jsonld_filename(&self) -> String {
        get_jsonld_filename(self)
    }

    fn referenced_cids(&self) -> Vec<String> {
        let mut refs = vec![];

        // include credential subject
        match &self.credential.id {
            Some(StringOrURI::String(s)) => refs.push(s.clone()),
            Some(StringOrURI::URI(u)) => match u {
                ssi::vc::URI::String(s) => refs.push(s.clone()),
            },
            None => {}
        }

        // include credential evidence
        if let Some(evidence) = &self.credential.evidence {
            for ev in evidence {
                if let Some(props) = &ev.property_set {
                    for key in [
                        // `report` and `certificateChain` are used in everything but Azure
                        "report",
                        "certificateChain",
                        // `report` + the rest are used in TPM-based Azure attestation
                        "reportCertificateChain",
                        "tpmQuote",
                        "tpmQuoteSignature",
                        "tpmAKCertificate",
                        "tpmLog",
                        "azureBootLog",
                    ] {
                        if let Some(Value::String(id)) = props.get(key) {
                            refs.push(id.to_owned());
                        }
                    }
                }
            }
        }

        refs
    }
}

impl VcStatement {
    /// Creates a new verifiable credential statement.
    ///
    /// # Arguments
    ///
    /// * `credential` - The W3C Verifiable Credential to register.
    /// * `registered_by` - DID of the entity registering this statement.
    /// * `timestamp` - Optional ISO 8601 timestamp; uses current time if not provided.
    ///
    /// # Returns
    ///
    /// A new `VcStatement` with a computed CID as its identifier.
    pub async fn create(
        credential: Credential,
        registered_by: String,
        timestamp: Option<String>,
    ) -> Result<Self> {
        let type_ = "CredentialRegistration".to_owned();

        let statement = Self {
            context: ig_common_context_link(),
            id: String::from("in-progress"),
            type_,
            credential,
            registered_by,
            timestamp: format_timestamp(timestamp),
        };

        // compute real CID and set
        let id = compute_cid(&statement).await?;
        let statement = Self { id, ..statement };

        Ok(statement)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use chrono::{DateTime, Utc};
    use serde_json::json;
    use ssi::{one_or_many::OneOrMany, vc::Evidence};

    use super::*;
    use crate::models::statements::Statement;

    /// Creates a minimal valid W3C VC for testing
    fn create_test_credential() -> Credential {
        let vc_json = json!({
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

        Credential::from_json_unsigned(&serde_json::to_string(&vc_json).unwrap()).unwrap()
    }

    #[tokio::test]
    async fn create_vc_statement() {
        let credential = create_test_credential();
        let registered_by = "did:key:z6Mkw2PvzC9DHXiYQHMDRwyxCCV9n4EDc6vqqp1uyi9nrwsP";
        let timestamp = "2024-06-27T21:40:37Z";

        let statement = VcStatement::create(
            credential.clone(),
            registered_by.to_owned(),
            Some(timestamp.to_owned()),
        )
        .await
        .unwrap();

        assert_eq!(
            statement.type_, "CredentialRegistration",
            "Type match failed"
        );
        assert_eq!(
            statement.registered_by, registered_by,
            "RegisteredBy match failed"
        );
        assert_eq!(statement.timestamp, timestamp, "Timestamp match failed");
        assert_eq!(
            statement.context,
            ig_common_context_link(),
            "Context match failed"
        );
        assert!(
            statement.id.starts_with("urn:cid:"),
            "ID should be a CID URN"
        );
    }

    #[tokio::test]
    async fn create_vc_statement_no_timestamp() {
        let credential = create_test_credential();
        let registered_by = "did:key:z6Mkw2PvzC9DHXiYQHMDRwyxCCV9n4EDc6vqqp1uyi9nrwsP";

        let statement = VcStatement::create(credential, registered_by.to_owned(), None)
            .await
            .unwrap();

        // Verify a timestamp was generated
        let min_timestamp: DateTime<Utc> = "2024-01-01T00:00:00Z".parse().unwrap();
        let generated_timestamp: DateTime<Utc> = statement.timestamp.parse().unwrap();
        assert!(
            generated_timestamp > min_timestamp,
            "Generated timestamp should be recent"
        );
    }

    #[tokio::test]
    async fn create_vc_statement_deterministic_cid() {
        let credential = create_test_credential();
        let registered_by = "did:key:z6Mkw2PvzC9DHXiYQHMDRwyxCCV9n4EDc6vqqp1uyi9nrwsP";
        let timestamp = "2024-06-27T21:40:37Z";

        // Create two statements with the same inputs
        let statement1 = VcStatement::create(
            credential.clone(),
            registered_by.to_owned(),
            Some(timestamp.to_owned()),
        )
        .await
        .unwrap();

        let statement2 = VcStatement::create(
            credential,
            registered_by.to_owned(),
            Some(timestamp.to_owned()),
        )
        .await
        .unwrap();

        // CIDs should be identical for same inputs
        assert_eq!(statement1.id, statement2.id, "CIDs should be deterministic");
    }

    #[tokio::test]
    async fn referenced_cids_extracts_credential_id() {
        let credential = create_test_credential();
        let registered_by = "did:key:z6Mkw2PvzC9DHXiYQHMDRwyxCCV9n4EDc6vqqp1uyi9nrwsP";
        let timestamp = "2024-06-27T21:40:37Z";

        let statement = VcStatement::create(
            credential,
            registered_by.to_owned(),
            Some(timestamp.to_owned()),
        )
        .await
        .unwrap();

        let refs = statement.referenced_cids();

        // Should contain the credential ID
        assert!(
            refs.contains(&"urn:uuid:12345678-1234-1234-1234-123456789012".to_string()),
            "Should reference the credential ID"
        );
    }

    #[tokio::test]
    async fn referenced_cids_extracts_evidence_properties() {
        let mut credential = create_test_credential();
        let mut property_set = HashMap::new();
        property_set.insert("report".to_string(), json!("urn:cid:reportcid"));
        property_set.insert("certificateChain".to_string(), json!("urn:cid:chaincid"));
        property_set.insert("tpmLog".to_string(), json!("urn:cid:logcid"));
        credential.evidence = Some(OneOrMany::One(Evidence {
            id: None,
            type_: vec!["AttestationEvidence".to_string()],
            property_set: Some(property_set),
        }));

        let statement = VcStatement::create(
            credential,
            "did:key:z6Mkw2PvzC9DHXiYQHMDRwyxCCV9n4EDc6vqqp1uyi9nrwsP".to_owned(),
            Some("2024-06-27T21:40:37Z".to_owned()),
        )
        .await
        .unwrap();

        let refs = statement.referenced_cids();

        assert!(refs.contains(&"urn:cid:reportcid".to_string()));
        assert!(refs.contains(&"urn:cid:chaincid".to_string()));
        assert!(refs.contains(&"urn:cid:logcid".to_string()));
    }

    #[tokio::test]
    async fn deserialize_vc_statement() {
        // First create a statement to get a valid structure
        let credential = create_test_credential();
        let registered_by = "did:key:z6Mkw2PvzC9DHXiYQHMDRwyxCCV9n4EDc6vqqp1uyi9nrwsP";
        let timestamp = "2024-06-27T21:40:37Z";

        let original = VcStatement::create(
            credential,
            registered_by.to_owned(),
            Some(timestamp.to_owned()),
        )
        .await
        .unwrap();

        // Serialize and deserialize through the Statement enum
        let json_value = serde_json::to_value(&original).unwrap();
        let deserialized: Statement = serde_json::from_value(json_value).unwrap();

        if let Statement::CredentialRegistration(vc_statement) = deserialized {
            assert_eq!(vc_statement.get_id(), original.get_id(), "ID match failed");
            assert_eq!(
                vc_statement.registered_by, original.registered_by,
                "RegisteredBy match failed"
            );
            assert_eq!(
                vc_statement.timestamp, original.timestamp,
                "Timestamp match failed"
            );
        } else {
            panic!("Expected CredentialRegistration variant");
        }
    }

    #[tokio::test]
    async fn vc_statement_jsonld_filename() {
        let credential = create_test_credential();
        let registered_by = "did:key:z6Mkw2PvzC9DHXiYQHMDRwyxCCV9n4EDc6vqqp1uyi9nrwsP";
        let timestamp = "2024-06-27T21:40:37Z";

        let statement = VcStatement::create(
            credential,
            registered_by.to_owned(),
            Some(timestamp.to_owned()),
        )
        .await
        .unwrap();

        let filename = statement.jsonld_filename();
        assert!(
            filename.ends_with(".jsonld"),
            "Filename should end with .jsonld"
        );

        // The filename should be based on the CID
        let cid = statement.get_id_no_prefix();
        assert_eq!(
            filename,
            format!("{}.jsonld", cid),
            "Filename should match CID"
        );
    }

    #[tokio::test]
    async fn vc_statement_jcs_serialization() {
        let credential = create_test_credential();
        let registered_by = "did:key:z6Mkw2PvzC9DHXiYQHMDRwyxCCV9n4EDc6vqqp1uyi9nrwsP";
        let timestamp = "2024-06-27T21:40:37Z";

        let statement = VcStatement::create(
            credential,
            registered_by.to_owned(),
            Some(timestamp.to_owned()),
        )
        .await
        .unwrap();

        // Should be able to serialize to JCS without errors
        let jcs = serde_jcs::to_string(&statement);
        assert!(jcs.is_ok(), "JCS serialization should succeed");

        // Verify the JCS output contains expected fields
        let jcs_string = jcs.unwrap();
        assert!(jcs_string.contains("\"@type\":\"CredentialRegistration\""));
        assert!(jcs_string.contains(
            "\"registeredBy\":\"did:key:z6Mkw2PvzC9DHXiYQHMDRwyxCCV9n4EDc6vqqp1uyi9nrwsP\""
        ));
    }

    #[tokio::test]
    async fn referenced_cids_no_credential_id() {
        // Credential without an `id` field produces no refs from that field
        let vc_json = json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential"],
            "issuer": "did:key:z6Mkw2PvzC9DHXiYQHMDRwyxCCV9n4EDc6vqqp1uyi9nrwsP",
            "issuanceDate": "2024-01-01T00:00:00Z",
            "credentialSubject": {
                "id": "urn:cid:bafkr4ibthuzk3zug7ghmx63yjqaiu6rx4hhfdv3453j5bodskgw57bx2ya"
            }
        });
        let credential =
            Credential::from_json_unsigned(&serde_json::to_string(&vc_json).unwrap()).unwrap();

        let statement = VcStatement::create(
            credential,
            "did:key:z6Mkw2PvzC9DHXiYQHMDRwyxCCV9n4EDc6vqqp1uyi9nrwsP".to_owned(),
            Some("2024-06-27T21:40:37Z".to_owned()),
        )
        .await
        .unwrap();

        // No credential id means no refs from that path
        let refs = statement.referenced_cids();
        assert!(
            refs.is_empty(),
            "Expected no refs when credential has no id"
        );
    }

    #[tokio::test]
    async fn referenced_cids_all_eight_evidence_keys() {
        let mut credential = create_test_credential();
        // Strip credential id so refs come exclusively from evidence
        credential.id = None;

        let mut props = HashMap::new();
        props.insert("report".to_string(), json!("urn:cid:report"));
        props.insert("certificateChain".to_string(), json!("urn:cid:chain"));
        props.insert(
            "reportCertificateChain".to_string(),
            json!("urn:cid:rchain"),
        );
        props.insert("tpmQuote".to_string(), json!("urn:cid:quote"));
        props.insert("tpmQuoteSignature".to_string(), json!("urn:cid:quotesig"));
        props.insert("tpmAKCertificate".to_string(), json!("urn:cid:akcert"));
        props.insert("tpmLog".to_string(), json!("urn:cid:tpmlog"));
        props.insert("azureBootLog".to_string(), json!("urn:cid:bootlog"));
        credential.evidence = Some(OneOrMany::One(Evidence {
            id: None,
            type_: vec!["AttestationEvidence".to_string()],
            property_set: Some(props),
        }));

        let statement = VcStatement::create(
            credential,
            "did:key:z6Mkw2PvzC9DHXiYQHMDRwyxCCV9n4EDc6vqqp1uyi9nrwsP".to_owned(),
            Some("2024-06-27T21:40:37Z".to_owned()),
        )
        .await
        .unwrap();

        let refs = statement.referenced_cids();
        assert_eq!(refs.len(), 8, "All eight evidence keys should be extracted");
        for expected in &[
            "urn:cid:report",
            "urn:cid:chain",
            "urn:cid:rchain",
            "urn:cid:quote",
            "urn:cid:quotesig",
            "urn:cid:akcert",
            "urn:cid:tpmlog",
            "urn:cid:bootlog",
        ] {
            assert!(
                refs.contains(&expected.to_string()),
                "Missing ref: {expected}"
            );
        }
    }

    #[tokio::test]
    async fn referenced_cids_skips_non_string_evidence_values() {
        let mut credential = create_test_credential();
        credential.id = None;

        let mut props = HashMap::new();
        props.insert("report".to_string(), json!(42)); // number, not a string
        props.insert("certificateChain".to_string(), json!(true)); // bool, not a string
        props.insert("tpmLog".to_string(), json!("urn:cid:validcid")); // valid
        credential.evidence = Some(OneOrMany::One(Evidence {
            id: None,
            type_: vec!["AttestationEvidence".to_string()],
            property_set: Some(props),
        }));

        let statement = VcStatement::create(
            credential,
            "did:key:z6Mkw2PvzC9DHXiYQHMDRwyxCCV9n4EDc6vqqp1uyi9nrwsP".to_owned(),
            Some("2024-06-27T21:40:37Z".to_owned()),
        )
        .await
        .unwrap();

        let refs = statement.referenced_cids();
        assert_eq!(refs, vec!["urn:cid:validcid".to_string()]);
    }

    #[tokio::test]
    async fn referenced_cids_multiple_evidence_entries() {
        let mut credential = create_test_credential();
        credential.id = None;

        let mut props1 = HashMap::new();
        props1.insert("report".to_string(), json!("urn:cid:report1"));
        let mut props2 = HashMap::new();
        props2.insert("report".to_string(), json!("urn:cid:report2"));

        credential.evidence = Some(OneOrMany::Many(vec![
            Evidence {
                id: None,
                type_: vec!["AttestationEvidence".to_string()],
                property_set: Some(props1),
            },
            Evidence {
                id: None,
                type_: vec!["AttestationEvidence".to_string()],
                property_set: Some(props2),
            },
        ]));

        let statement = VcStatement::create(
            credential,
            "did:key:z6Mkw2PvzC9DHXiYQHMDRwyxCCV9n4EDc6vqqp1uyi9nrwsP".to_owned(),
            Some("2024-06-27T21:40:37Z".to_owned()),
        )
        .await
        .unwrap();

        let refs = statement.referenced_cids();
        assert_eq!(refs.len(), 2);
        assert!(refs.contains(&"urn:cid:report1".to_string()));
        assert!(refs.contains(&"urn:cid:report2".to_string()));
    }

    #[tokio::test]
    async fn different_inputs_produce_different_cids() {
        let credential = create_test_credential();
        let registered_by = "did:key:z6Mkw2PvzC9DHXiYQHMDRwyxCCV9n4EDc6vqqp1uyi9nrwsP";
        let timestamp = "2024-06-27T21:40:37Z";

        let s1 = VcStatement::create(
            credential.clone(),
            registered_by.to_owned(),
            Some(timestamp.to_owned()),
        )
        .await
        .unwrap();

        let s2 = VcStatement::create(
            credential,
            "did:key:z6MksNPQf5wQwQfA2a5JY9xY8h6CZ9nHp4Y5qpc4kTYqN6xw".to_owned(),
            Some(timestamp.to_owned()),
        )
        .await
        .unwrap();

        assert_ne!(
            s1.id, s2.id,
            "Different registeredBy should produce different CIDs"
        );
    }

    #[tokio::test]
    async fn get_type_string_returns_credential_registration() {
        let statement = VcStatement::create(
            create_test_credential(),
            "did:key:z6Mkw2PvzC9DHXiYQHMDRwyxCCV9n4EDc6vqqp1uyi9nrwsP".to_owned(),
            Some("2024-06-27T21:40:37Z".to_owned()),
        )
        .await
        .unwrap();

        let type_string = statement.get_type_string().unwrap();
        assert_eq!(type_string, "CredentialRegistration");
    }
}
