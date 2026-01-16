use anyhow::Result;
use serde::{Deserialize, Serialize};

use super::{compute_cid, format_timestamp, get_jsonld_filename, StatementTrait};
use crate::{cid::prepend_urn_cid, json_ld::ig_common_context_link};

#[derive(Clone, Debug, Serialize, Deserialize, utoipa::ToSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AssociationStatement {
    #[serde(rename = "@context")]
    pub context: String,
    #[serde(rename = "@id")]
    id: String,
    #[serde(rename = "@type")]
    pub type_: String,
    pub subject: String,
    pub association: String,
    pub registered_by: String,
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
        vec![self.association.clone(), self.subject.clone()]
    }
}

impl AssociationStatement {
    pub async fn create(
        subject: String,
        association: String,
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

        let association = if association.starts_with("urn:") || association.starts_with("did:") {
            association
        } else {
            // if `association` string is not a URN or DID, assume it's a CID
            prepend_urn_cid(association.as_str())?
        };

        let statement = Self {
            context: ig_common_context_link(),
            id: String::from("in-progress"),
            type_,
            subject,
            association,
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
    use crate::lineage::models::statements::Statement;

    #[tokio::test]
    async fn generate_association_statement() {
        let statement = json!({
            // to update @id, run statement through a rdf-c generator or run the test to let it compute the @id
            "@id": "urn:cid:bagb6qaq6eaujjh6k6yitzoojs7p6dn77xwt2iz3nqyxoot6s5anma3ygpgutk",
            "@context": ig_common_context_link(),
            "@type": "AssociationRegistration",
            "subject": "urn:cid:abc",
            "association": "urn:cid:def",
            "registeredBy": "did:key:abc",
            "timestamp": "1970-01-01T00:00:00Z",
        });

        let statement_jcs = serde_jcs::to_string(&statement).unwrap();

        let generated_statement = AssociationStatement::create(
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
    async fn generate_association_statement_no_prefix() {
        let statement = json!({
            // to update @id, run statement through a rdf-c generator or run the test to let it compute the @id
            "@id": "urn:cid:bagb6qaq6eaujjh6k6yitzoojs7p6dn77xwt2iz3nqyxoot6s5anma3ygpgutk",
            "@context": ig_common_context_link(),
            "@type": "AssociationRegistration",
            "subject": "urn:cid:abc",
            "association": "urn:cid:def",
            "registeredBy": "did:key:abc",
            "timestamp": "1970-01-01T00:00:00Z",
        });

        let statement_jcs = serde_jcs::to_string(&statement).unwrap();

        let generated_statement = AssociationStatement::create(
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
          "@type": "AssociationRegistration",
          "@context": "urn:cid:bafkr4ibb27ow5o2yukccjjyrcunsk6jw4muacuk22cny7qdlw5wkfwxl2u",
          "@id": "urn:cid:bagb6qaq6ebxbtd4ykyobejg7hdx7xvngldjo5ntzhpjngqk7eeobtcxe4suni",
          "subject": "urn:cid:bafkr4ibthuzk3zug7ghmx63yjqaiu6rx4hhfdv3453j5bodskgw57bx2ya",
          "association": "urn:cid:baga6yaq6echz7kjzuhzubnsq2mqkw5oxpkrio5nwb4fibzkwaqke3hqbc25g4",
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
                "urn:cid:baga6yaq6echz7kjzuhzubnsq2mqkw5oxpkrio5nwb4fibzkwaqke3hqbc25g4"
            );
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
