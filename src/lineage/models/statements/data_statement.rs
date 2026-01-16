use anyhow::Result;
use serde::{Deserialize, Serialize};

use super::{
    compute_cid, format_cids, format_timestamp, get_jsonld_filename, StatementTrait, ValueOrArray,
};
use crate::json_ld::ig_common_context_link;

#[derive(Clone, Debug, Serialize, Deserialize, utoipa::ToSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DataStatement {
    #[serde(rename = "@context")]
    pub context: String,
    #[serde(rename = "@id")]
    id: String,
    #[serde(rename = "@type")]
    pub type_: String,
    #[schema(value_type = String)]
    pub data: ValueOrArray<String>,
    pub registered_by: String,
    pub timestamp: String,
}

impl StatementTrait for DataStatement {
    fn get_id(&self) -> String {
        self.id.clone()
    }

    fn jsonld_filename(&self) -> String {
        get_jsonld_filename(self)
    }

    fn referenced_cids(&self) -> Vec<String> {
        match &self.data {
            ValueOrArray::Value(v) => vec![v.clone()],
            ValueOrArray::Array(a) => a.clone(),
        }
    }
}

impl DataStatement {
    /// Creates a new DataRegistrationStatement object.
    /// `data` cids will be prepended with `urn:cid:` if not already formatted with the prefix
    pub async fn create(
        data: Vec<String>,
        registered_by: String,
        timestamp: Option<String>,
    ) -> Result<Self> {
        let data = format_cids(data)?;

        let type_ = "DataRegistration".to_owned();

        let statement = Self {
            context: ig_common_context_link(),
            id: String::from("in-progress"),
            type_,
            data,
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
    async fn generate_data_statement_single_cid() {
        let id = "urn:cid:bagb6qaq6ea37jzd3jsdloy7nfjo5xpxeh2yly5o3pmq5dbyk2eqw6x53nxsbo";
        let context = ig_common_context_link();
        let type_ = "DataRegistration";
        let data = "urn:cid:data_cid";
        let registered_by = "did:key:zQ3shtdnadpYS81njBma5RqQMEAL3BenSJdCfZAu2Uj1ukwo9";
        let timestamp = "2024-06-27T21:40:37Z";

        let s = DataStatement::create(
            vec![data.to_owned()],
            registered_by.to_owned(),
            Some(timestamp.to_owned()),
        )
        .await
        .unwrap();

        assert_eq!(
            s.data,
            ValueOrArray::Value(data.to_owned()),
            "Data match failed"
        );
        assert_eq!(s.registered_by, registered_by, "RegisteredBy match failed");

        assert_eq!(s.id, id, "ID match failed");
        assert_eq!(s.timestamp, timestamp, "Timestamp match failed");
        assert_eq!(s.context, context, "Context match failed");
        assert_eq!(s.type_, type_, "Type match failed");
    }

    #[tokio::test]
    async fn generate_data_statement_empty_cid() {
        let s = DataStatement::create(
            vec!["".to_string()],
            "did:key:zQ3shtdnadpYS81njBma5RqQMEAL3BenSJdCfZAu2Uj1ukwo9".to_string(),
            Some("2024-06-27T21:40:37Z".to_string()),
        )
        .await;

        assert!(s.is_err());
        assert_eq!(s.unwrap_err().to_string(), "CID list must not be empty.");
    }

    #[tokio::test]
    async fn generate_data_statement_multi_cid() {
        let id = "urn:cid:bagb6qaq6ecwy2fzlj7oq6sxa3onzam7zce6ny23tuog6hx2rbt3vk6bzokqs6";
        let context = ig_common_context_link();
        let type_ = "DataRegistration";
        let data = vec![
            "urn:cid:data_cid1".to_owned(),
            "urn:cid:cid2".to_owned(),
            "urn:cid:cid3".to_owned(),
            "urn:cid:and_number_4".to_owned(),
        ];
        let registered_by = "did:key:zQ3shtdnadpYS81njBma5RqQMEAL3BenSJdCfZAu2Uj1ukwo9";
        let timestamp = "2024-06-27T21:40:37Z";

        let s = DataStatement::create(
            vec![
                "urn:cid:data_cid1".to_owned(),
                "urn:cid:cid2".to_owned(),
                "".to_owned(),
                "cid3".to_owned(),
                "and_number_4".to_owned(),
            ],
            registered_by.to_owned(),
            Some(timestamp.to_owned()),
        )
        .await
        .unwrap();

        assert_eq!(s.data, ValueOrArray::Array(data), "Data match failed");
        assert_eq!(s.registered_by, registered_by, "RegisteredBy match failed");

        assert_eq!(s.id, id, "ID match failed");
        assert_eq!(s.timestamp, timestamp, "Timestamp match failed");
        assert_eq!(s.context, context, "Context match failed");
        assert_eq!(s.type_, type_, "Type match failed");
    }

    #[tokio::test]
    async fn generate_data_statement_no_timestamp() {
        let context = ig_common_context_link();
        let type_ = "DataRegistration";
        let data = "urn:cid:data_cid";
        let registered_by = "did:key:zQ3shtdnadpYS81njBma5RqQMEAL3BenSJdCfZAu2Uj1ukwo9";

        let s = DataStatement::create(vec![data.to_owned()], registered_by.to_owned(), None)
            .await
            .unwrap();

        let min_timestamp: DateTime<Utc> = "2024-06-27T14:00:00Z".parse().unwrap();
        let generated_timestamp: DateTime<Utc> = s.timestamp.parse().unwrap();
        assert!(generated_timestamp > min_timestamp);

        assert_eq!(
            s.data,
            ValueOrArray::Value(data.to_owned()),
            "Data match failed"
        );
        assert_eq!(s.registered_by, registered_by, "RegisteredBy match failed");

        assert_eq!(s.context, context, "Context match failed");
        assert_eq!(s.type_, type_, "Type match failed");
    }

    #[tokio::test]
    async fn derserialize_statement() {
        let json = json!({
            "@type": "DataRegistration",
            "@context": "urn:cid:bafkr4ibb27ow5o2yukccjjyrcunsk6jw4muacuk22cny7qdlw5wkfwxl2u",
            "@id": "urn:cid:bagb6qaq6ectmw6nmurkplcs7egavvupz3jeejq5qf6el4zmbli2c4hnokiico",
            "data": "urn:cid:bafkr4iensszfrkcq3medrmxpawmr5zpres3j2p6d6omvqooeegeesgwslu",
            "registeredBy": "did:key:z6Mkw2PvzC9DHXiYQHMDRwyxCCV9n4EDc6vqqp1uyi9nrwsP",
            "timestamp": "2025-04-04T22:28:35Z"
        });

        let statement: Statement = serde_json::from_value(json).unwrap();

        if let Statement::DataRegistration(data) = statement {
            assert_eq!(
                data.id,
                "urn:cid:bagb6qaq6ectmw6nmurkplcs7egavvupz3jeejq5qf6el4zmbli2c4hnokiico"
            );
            assert_eq!(
                data.registered_by,
                "did:key:z6Mkw2PvzC9DHXiYQHMDRwyxCCV9n4EDc6vqqp1uyi9nrwsP"
            );
            assert_eq!(data.timestamp, "2025-04-04T22:28:35Z");
        } else {
            panic!("Expected DataRegistration variant");
        }
    }
}
