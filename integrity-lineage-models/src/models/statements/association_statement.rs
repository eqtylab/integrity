use anyhow::Result;
use integrity_jsonld::ig_common_context_link;
use serde::{Deserialize, Serialize};

use super::{compute_cid, format_timestamp, get_jsonld_filename, StatementTrait};
use crate::cid::prepend_urn_cid;

#[derive(Clone, Debug, Serialize, Deserialize, utoipa::ToSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum AssociationType {
    Certifies,
    Includes,
    IsInstanceOf,
}

/// Records an association between a subject and another entity
///
/// This statement type is used to create relationships between artifacts,
/// such as linking data to its metadata, or connecting related entities.
#[derive(Clone, Debug, Serialize, Deserialize, utoipa::ToSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AssociationStatement {
    /// JSON-LD context URL
    #[serde(rename = "@context")]
    pub context: String,
    /// Unique identifier for this statement
    #[serde(rename = "@id")]
    id: String,
    /// Statement type identifier
    #[serde(rename = "@type")]
    pub type_: String,
    /// The subject of the association (CID or DID)
    pub subject: String,
    /// The associated entities (CID or DID)
    pub association: Vec<String>,
    /// Type of the association
    #[serde(rename = "type")]
    pub r#type: AssociationType,
    /// DID of the entity that registered this statement
    pub registered_by: String,
    /// ISO 8601 timestamp of when the statement was created
    pub timestamp: String,
}

impl StatementTrait for AssociationStatement {
    fn get_id(&self) -> String {
        self.id.clone()
    }

    fn jsonld_filename(&self) -> String {
        get_jsonld_filename(self)
    }

    fn referenced_cids(&self) -> Vec<String> {
        let mut cids = self.association.clone();
        cids.push(self.subject.clone());
        cids
    }
}

impl AssociationStatement {
    /// Creates a new association statement linking a subject to an associated entity.
    ///
    /// # Arguments
    ///
    /// * `subject` - The subject of the association (CID or DID). If not prefixed, assumed to be a CID.
    /// * `association` - The associated entities (CID or DID). If not prefixed, assumed to be a CID.
    /// * `type` - The type of association.
    /// * `registered_by` - DID of the entity registering this statement.
    /// * `timestamp` - Optional ISO 8601 timestamp; uses current time if not provided.
    ///
    /// # Returns
    ///
    /// A new `AssociationStatement` with a computed CID as its identifier.
    pub async fn create(
        subject: String,
        association: Vec<String>,
        r#type: AssociationType,
        registered_by: String,
        timestamp: Option<String>,
    ) -> Result<Self> {
        let type_ = "AssociationRegistration".to_owned();

        let subject = if subject.starts_with("urn:") || subject.starts_with("did:") {
            subject
        } else {
            // if `subject` string is not a URN or DID, assume it's a CID
            prepend_urn_cid(subject.as_str())?
        };

        let association = association
            .into_iter()
            .map(|value| {
                if value.starts_with("urn:") || value.starts_with("did:") {
                    Ok(value)
                } else {
                    // if `association` string is not a URN or DID, assume it's a CID
                    prepend_urn_cid(value.as_str())
                }
            })
            .collect::<Result<Vec<_>>>()?;

        let statement = Self {
            context: ig_common_context_link(),
            id: String::from("in-progress"),
            type_,
            subject,
            association,
            r#type,
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
    use serde_json::json;

    use super::*;
    use crate::models::statements::Statement;

    #[tokio::test]
    async fn generate_association_statement() {
        let generated_statement = AssociationStatement::create(
            "urn:cid:abc".to_owned(),
            vec!["urn:cid:def".to_owned()],
            AssociationType::Certifies,
            "did:key:abc".to_owned(),
            Some("1970-01-01T00:00:00Z".to_owned()),
        )
        .await
        .unwrap();

        let mut statement = json!({
            "@id": "in-progress",
            "@context": ig_common_context_link(),
            "@type": "AssociationRegistration",
            "subject": "urn:cid:abc",
            "association": ["urn:cid:def"],
            "type": "certifies",
            "registeredBy": "did:key:abc",
            "timestamp": "1970-01-01T00:00:00Z",
        });
        statement["@id"] = json!(generated_statement.id);

        let statement_jcs = serde_jcs::to_string(&statement).unwrap();
        let generated_statement_jcs = serde_jcs::to_string(&generated_statement).unwrap();

        assert_eq!(generated_statement_jcs, statement_jcs);
    }

    #[tokio::test]
    async fn generate_association_statement_no_prefix() {
        let generated_statement = AssociationStatement::create(
            "abc".to_owned(),
            vec!["def".to_owned()],
            AssociationType::Includes,
            "did:key:abc".to_owned(),
            Some("1970-01-01T00:00:00Z".to_owned()),
        )
        .await
        .unwrap();

        let mut statement = json!({
            "@id": "in-progress",
            "@context": ig_common_context_link(),
            "@type": "AssociationRegistration",
            "subject": "urn:cid:abc",
            "association": ["urn:cid:def"],
            "type": "includes",
            "registeredBy": "did:key:abc",
            "timestamp": "1970-01-01T00:00:00Z",
        });
        statement["@id"] = json!(generated_statement.id);

        let statement_jcs = serde_jcs::to_string(&statement).unwrap();
        let generated_statement_jcs = serde_jcs::to_string(&generated_statement).unwrap();

        assert_eq!(generated_statement_jcs, statement_jcs);
    }

    #[tokio::test]
    async fn deserialize_statement() {
        let json = json!({
          "@type": "AssociationRegistration",
          "@context": "urn:cid:bafkr4ibb27ow5o2yukccjjyrcunsk6jw4muacuk22cny7qdlw5wkfwxl2u",
          "@id": "urn:cid:bagb6qaq6ebxbtd4ykyobejg7hdx7xvngldjo5ntzhpjngqk7eeobtcxe4suni",
          "subject": "urn:cid:bafkr4ibthuzk3zug7ghmx63yjqaiu6rx4hhfdv3453j5bodskgw57bx2ya",
          "association": ["urn:cid:baga6yaq6echz7kjzuhzubnsq2mqkw5oxpkrio5nwb4fibzkwaqke3hqbc25g4"],
          "type": "isInstanceOf",
          "registeredBy": "did:key:z6Mkw2PvzC9DHXiYQHMDRwyxCCV9n4EDc6vqqp1uyi9nrwsP",
          "timestamp": "2025-04-04T22:28:36Z"
        });

        let statement: Statement = serde_json::from_value(json).unwrap();

        if let Statement::AssociationRegistration(association) = statement {
            assert_eq!(
                association.id,
                "urn:cid:bagb6qaq6ebxbtd4ykyobejg7hdx7xvngldjo5ntzhpjngqk7eeobtcxe4suni"
            );
            assert_eq!(
                association.subject,
                "urn:cid:bafkr4ibthuzk3zug7ghmx63yjqaiu6rx4hhfdv3453j5bodskgw57bx2ya"
            );
            assert_eq!(
                association.association,
                vec![
                    "urn:cid:baga6yaq6echz7kjzuhzubnsq2mqkw5oxpkrio5nwb4fibzkwaqke3hqbc25g4"
                        .to_owned()
                ]
            );
            assert_eq!(association.r#type, AssociationType::IsInstanceOf);
            assert_eq!(
                association.registered_by,
                "did:key:z6Mkw2PvzC9DHXiYQHMDRwyxCCV9n4EDc6vqqp1uyi9nrwsP"
            );
            assert_eq!(association.timestamp, "2025-04-04T22:28:36Z");
        } else {
            panic!("Expected AssociationRegistration variant");
        }
    }
}
