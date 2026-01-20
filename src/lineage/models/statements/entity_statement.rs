use anyhow::Result;
use serde::{Deserialize, Serialize};

use super::{
    compute_cid, format_timestamp, format_uuids, get_jsonld_filename, StatementTrait, ValueOrArray,
};
use crate::json_ld::ig_common_context_link;

/// Records the registration of entities in the lineage system
///
/// This statement type registers entities (organizations, systems, or agents)
/// that participate in lineage events, identified by UUIDs.
#[derive(Clone, Debug, Serialize, Deserialize, utoipa::ToSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EntityStatement {
    /// JSON-LD context URL
    #[serde(rename = "@context")]
    pub context: String,
    /// Unique identifier for this statement
    #[serde(rename = "@id")]
    id: String,
    /// Statement type identifier
    #[serde(rename = "@type")]
    pub type_: String,
    /// Entity UUID(s) being registered
    #[schema(value_type = String)]
    pub entity: ValueOrArray<String>,
    /// DID of the entity that registered this statement
    pub registered_by: String,
    /// ISO 8601 timestamp of when the statement was created
    pub timestamp: String,
}

impl StatementTrait for EntityStatement {
    fn get_id(&self) -> String {
        self.id.clone()
    }

    fn jsonld_filename(&self) -> String {
        get_jsonld_filename(self)
    }

    fn referenced_cids(&self) -> Vec<String> {
        vec![]
    }
}

impl EntityStatement {
    /// Creates a new EntityRegistrationStatement object.
    /// `entity` uuids will be prepended with `urn:uuid:` if not already formatted with the prefix
    pub async fn create(
        entity: Vec<String>,
        registered_by: String,
        timestamp: Option<String>,
    ) -> Result<Self> {
        let entity = format_uuids(entity)?;

        let type_ = "EntityRegistration".to_owned();

        let statement = Self {
            context: ig_common_context_link(),
            id: String::from("in-progress"),
            type_,
            entity,
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

    #[tokio::test]
    async fn generate_entity_statement_single_uuid() {
        let id = "urn:cid:bagb6qaq6ecrmjmwm7tpbtfan6r2d6mwvdm6c2jikbgevayni4w4kwjonk4ncs";
        let context = ig_common_context_link();
        let type_ = "EntityRegistration";
        let entity = "urn:uuid:entity_uuid";
        let registered_by = "did:key:zQ3shtdnadpYS81njBma5RqQMEAL3BenSJdCfZAu2Uj1ukwo9";
        let timestamp = "2024-06-27T21:40:37Z";

        let s = EntityStatement::create(
            vec![entity.to_owned()],
            registered_by.to_owned(),
            Some(timestamp.to_owned()),
        )
        .await
        .unwrap();

        assert_eq!(
            s.entity,
            ValueOrArray::Value(entity.to_owned()),
            "Entity match failed"
        );
        assert_eq!(s.registered_by, registered_by, "RegisteredBy match failed");

        assert_eq!(s.id, id, "ID match failed");
        assert_eq!(s.timestamp, timestamp, "Timestamp match failed");
        assert_eq!(s.context, context, "Context match failed");
        assert_eq!(s.type_, type_, "Type match failed");
    }

    #[tokio::test]
    async fn generate_entity_statement_empty_uuid() {
        let s = EntityStatement::create(
            vec!["".to_string()],
            "did:key:zQ3shtdnadpYS81njBma5RqQMEAL3BenSJdCfZAu2Uj1ukwo9".to_string(),
            Some("2024-06-27T21:40:37Z".to_string()),
        )
        .await;

        assert!(s.is_err());
        assert_eq!(s.unwrap_err().to_string(), "CID list must not be empty.");
    }

    #[tokio::test]
    async fn generate_entity_statement_multi_uuid() {
        let id = "urn:cid:bagb6qaq6edsenc3gbi2ymafzmn6l54kj427gmnwgjlh6wgglmppwmsvtgy3cw";
        let context = ig_common_context_link();
        let type_ = "EntityRegistration";
        let entity = vec![
            "urn:uuid:entity_uuid1".to_owned(),
            "urn:uuid:entity_uuid2".to_owned(),
            "urn:uuid:entity_uuid3".to_owned(),
            "urn:uuid:entity_uuid4".to_owned(),
        ];
        let registered_by = "did:key:zQ3shtdnadpYS81njBma5RqQMEAL3BenSJdCfZAu2Uj1ukwo9";
        let timestamp = "2024-06-27T21:40:37Z";

        let s = EntityStatement::create(
            vec![
                "urn:uuid:entity_uuid1".to_owned(),
                "urn:uuid:entity_uuid2".to_owned(),
                "".to_owned(),
                "entity_uuid3".to_owned(),
                "entity_uuid4".to_owned(),
            ],
            registered_by.to_owned(),
            Some(timestamp.to_owned()),
        )
        .await
        .unwrap();

        assert_eq!(s.entity, ValueOrArray::Array(entity), "Entity match failed");
        assert_eq!(s.registered_by, registered_by, "RegisteredBy match failed");

        assert_eq!(s.id, id, "ID match failed");
        assert_eq!(s.timestamp, timestamp, "Timestamp match failed");
        assert_eq!(s.context, context, "Context match failed");
        assert_eq!(s.type_, type_, "Type match failed");
    }

    #[tokio::test]
    async fn generate_entity_statement_no_timestamp() {
        let context = ig_common_context_link();
        let type_ = "EntityRegistration";
        let entity = "urn:uuid:entity_uuid";
        let registered_by = "did:key:zQ3shtdnadpYS81njBma5RqQMEAL3BenSJdCfZAu2Uj1ukwo9";

        let s = EntityStatement::create(vec![entity.to_owned()], registered_by.to_owned(), None)
            .await
            .unwrap();

        let min_timestamp: DateTime<Utc> = "2024-06-27T14:00:00Z".parse().unwrap();
        let generated_timestamp: DateTime<Utc> = s.timestamp.parse().unwrap();
        assert!(generated_timestamp > min_timestamp);

        assert_eq!(
            s.entity,
            ValueOrArray::Value(entity.to_owned()),
            "Entity match failed"
        );
        assert_eq!(s.registered_by, registered_by, "RegisteredBy match failed");

        assert_eq!(s.context, context, "Context match failed");
        assert_eq!(s.type_, type_, "Type match failed");
    }

    #[tokio::test]
    async fn derserialize_statement() {
        let json = json!({
            "@type": "EntityRegistration",
            "@context": "urn:uuid:bafkr4ibb27ow5o2yukccjjyrcunsk6jw4muacuk22cny7qdlw5wkfwxl2u",
            "@id": "urn:cid:bagb6qaq6ectmw6nmurkplcs7egavvupz3jeejq5qf6el4zmbli2c4hnokiico",
            "entity": "urn:uuid:d5a510b5-9388-45e9-a446-45d264e0926d",
            "registeredBy": "did:key:z6Mkw2PvzC9DHXiYQHMDRwyxCCV9n4EDc6vqqp1uyi9nrwsP",
            "timestamp": "2025-04-04T22:28:35Z"
        });

        let statement: Statement = serde_json::from_value(json).unwrap();

        if let Statement::EntityRegistration(entity) = statement {
            assert_eq!(
                entity.id,
                "urn:cid:bagb6qaq6ectmw6nmurkplcs7egavvupz3jeejq5qf6el4zmbli2c4hnokiico"
            );
            assert_eq!(
                entity.registered_by,
                "did:key:z6Mkw2PvzC9DHXiYQHMDRwyxCCV9n4EDc6vqqp1uyi9nrwsP"
            );
            assert_eq!(entity.timestamp, "2025-04-04T22:28:35Z");
        } else {
            panic!("Expected MetaentityRegistration variant");
        }
    }
}
