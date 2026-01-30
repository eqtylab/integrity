use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use ssi::vc::{Credential, StringOrURI};

use super::{compute_cid, format_timestamp, get_jsonld_filename, StatementTrait};
use crate::json_ld::ig_common_context_link;

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
    use chrono::{DateTime, Utc};
    use serde_json::json;

    use super::*;
    use crate::lineage::models::statements::Statement;

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
}
