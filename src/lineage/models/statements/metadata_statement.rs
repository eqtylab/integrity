use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{compute_cid, format_timestamp, get_jsonld_filename, StatementTrait};
use crate::{
    cid::{jcs::compute_jcs_cid, prepend_urn_cid},
    json_ld::ig_common_context_link,
};

/// Records metadata associated with a subject
///
/// This statement type links metadata (descriptive information, properties,
/// attributes) to artifacts or entities in the lineage system.
#[derive(Clone, Debug, Serialize, Deserialize, utoipa::ToSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MetadataStatement {
    /// JSON-LD context URL
    #[serde(rename = "@context")]
    pub context: String,
    /// Unique identifier for this statement
    #[serde(rename = "@id")]
    id: String,
    /// Statement type identifier
    #[serde(rename = "@type")]
    pub type_: String,
    /// The subject the metadata describes (CID or DID)
    pub subject: String,
    /// CID of the metadata JSON document
    pub metadata: String,
    /// DID of the entity that registered this statement
    pub registered_by: String,
    /// ISO 8601 timestamp of when the statement was created
    pub timestamp: String,
}

impl StatementTrait for MetadataStatement {
    fn get_id(&self) -> String {
        self.id.clone()
    }

    fn jsonld_filename(&self) -> String {
        get_jsonld_filename(self)
    }

    fn referenced_cids(&self) -> Vec<String> {
        vec![self.metadata.clone(), self.subject.clone()]
    }
}

impl MetadataStatement {
    pub async fn create(
        subject: String,
        metadata: String,
        registered_by: String,
        timestamp: Option<String>,
    ) -> Result<Self> {
        let type_ = "MetadataRegistration".to_owned();

        let subject = if subject.starts_with("urn:") || subject.starts_with("did:") {
            subject
        } else {
            // if subject string is not a URN or DID, assume it's a CID
            prepend_urn_cid(subject.as_str())?
        };

        let metadata = prepend_urn_cid(metadata.as_str())?;

        let statement = Self {
            context: ig_common_context_link(),
            id: String::from("in-progress"),
            type_,
            subject,
            metadata,
            registered_by,
            timestamp: format_timestamp(timestamp),
        };

        // compute real CID and set
        let id = compute_cid(&statement).await?;
        let statement = Self { id, ..statement };

        Ok(statement)
    }

    /// Creates a Metadata statement by computing the JCS Cid for the provided metadata Json Value
    pub async fn create_from_json(
        subject: String,
        metadata: Value,
        registered_by: String,
        timestamp: Option<String>,
    ) -> Result<Self> {
        let (metadata_cid, _canon_bytes) = compute_jcs_cid(&metadata)?;

        Self::create(subject, metadata_cid, registered_by, timestamp).await
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::lineage::models::statements::Statement;

    #[tokio::test]
    async fn generate_metadata_statement() {
        let statement = json!({
            // to update @id, run statement through a rdf-c generator or run the test to let it compute the @id
            "@id": "urn:cid:bagb6qaq6ed7lbsc4fyb57367zk3sclghloi7qtlkjbjszqrzu2j4tnuzzwip4",
            "@context": ig_common_context_link(),
            "@type": "MetadataRegistration",
            "subject": "urn:cid:abc",
            "metadata": "urn:cid:def",
            "registeredBy": "did:key:abc",
            "timestamp": "1970-01-01T00:00:00Z",
        });

        let statement_jcs = serde_jcs::to_string(&statement).unwrap();

        let generated_statement = MetadataStatement::create(
            "urn:cid:abc".to_owned(),
            "urn:cid:def".to_owned(),
            "did:key:abc".to_owned(),
            Some("1970-01-01T00:00:00Z".to_owned()),
        )
        .await
        .unwrap();

        let generated_statement_jcs = serde_jcs::to_string(&generated_statement).unwrap();

        assert_eq!(generated_statement_jcs, statement_jcs);
    }

    #[tokio::test]
    async fn generate_metadata_statement_no_prefix() {
        let statement = json!({
            // to update @id, run statement through a rdf-c generator or run the test to let it compute the @id
            "@id": "urn:cid:bagb6qaq6ed7lbsc4fyb57367zk3sclghloi7qtlkjbjszqrzu2j4tnuzzwip4",
            "@context": ig_common_context_link(),
            "@type": "MetadataRegistration",
            "subject": "urn:cid:abc",
            "metadata": "urn:cid:def",
            "registeredBy": "did:key:abc",
            "timestamp": "1970-01-01T00:00:00Z",
        });

        let statement_jcs = serde_jcs::to_string(&statement).unwrap();

        let generated_statement = MetadataStatement::create(
            "abc".to_owned(),
            "def".to_owned(),
            "did:key:abc".to_owned(),
            Some("1970-01-01T00:00:00Z".to_owned()),
        )
        .await
        .unwrap();

        let generated_statement_jcs = serde_jcs::to_string(&generated_statement).unwrap();

        assert_eq!(generated_statement_jcs, statement_jcs);
    }

    #[tokio::test]
    async fn deserialize_statement() {
        let json = json!({
          "@type": "MetadataRegistration",
          "@context": "urn:cid:bafkr4ibb27ow5o2yukccjjyrcunsk6jw4muacuk22cny7qdlw5wkfwxl2u",
          "@id": "urn:cid:bagb6qaq6ebxbtd4ykyobejg7hdx7xvngldjo5ntzhpjngqk7eeobtcxe4suni",
          "subject": "urn:cid:bafkr4ibthuzk3zug7ghmx63yjqaiu6rx4hhfdv3453j5bodskgw57bx2ya",
          "metadata": "urn:cid:baga6yaq6echz7kjzuhzubnsq2mqkw5oxpkrio5nwb4fibzkwaqke3hqbc25g4",
          "registeredBy": "did:key:z6Mkw2PvzC9DHXiYQHMDRwyxCCV9n4EDc6vqqp1uyi9nrwsP",
          "timestamp": "2025-04-04T22:28:36Z"
        });

        let statement: Statement = serde_json::from_value(json).unwrap();

        if let Statement::MetadataRegistration(metadata) = statement {
            assert_eq!(
                metadata.id,
                "urn:cid:bagb6qaq6ebxbtd4ykyobejg7hdx7xvngldjo5ntzhpjngqk7eeobtcxe4suni"
            );
            assert_eq!(
                metadata.subject,
                "urn:cid:bafkr4ibthuzk3zug7ghmx63yjqaiu6rx4hhfdv3453j5bodskgw57bx2ya"
            );
            assert_eq!(
                metadata.metadata,
                "urn:cid:baga6yaq6echz7kjzuhzubnsq2mqkw5oxpkrio5nwb4fibzkwaqke3hqbc25g4"
            );
            assert_eq!(
                metadata.registered_by,
                "did:key:z6Mkw2PvzC9DHXiYQHMDRwyxCCV9n4EDc6vqqp1uyi9nrwsP"
            );
            assert_eq!(metadata.timestamp, "2025-04-04T22:28:36Z");
        } else {
            panic!("Expected MetadataRegistration variant");
        }
    }
}
