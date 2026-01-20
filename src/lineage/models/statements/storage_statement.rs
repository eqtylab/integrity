use anyhow::Result;
use serde::{Deserialize, Serialize};

use super::{compute_cid, format_timestamp, get_jsonld_filename, StatementTrait};
use crate::{cid::prepend_urn_cid, json_ld::ig_common_context_link};

/// Records the storage of data on a specific system
///
/// This statement type captures where data is stored and who operated
/// the storage system, creating an audit trail for data location.
#[derive(Clone, Debug, Serialize, Deserialize, utoipa::ToSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct StorageStatement {
    /// JSON-LD context URL
    #[serde(rename = "@context")]
    pub context: String,
    /// Unique identifier for this statement
    #[serde(rename = "@id")]
    id: String,
    /// Statement type identifier
    #[serde(rename = "@type")]
    pub type_: String,
    /// DID of the entity that registered this statement
    pub registered_by: String,
    /// ISO 8601 timestamp of when the statement was created
    pub timestamp: String,
    /// CID of the data being stored
    pub data: String,
    /// CID of the storage system description
    pub stored_on: String,
    /// DID of the entity operating the storage system
    pub operated_by: String,
}

impl StatementTrait for StorageStatement {
    fn get_id(&self) -> String {
        self.id.clone()
    }

    fn jsonld_filename(&self) -> String {
        get_jsonld_filename(self)
    }

    fn referenced_cids(&self) -> Vec<String> {
        vec![self.data.clone(), self.stored_on.clone()]
    }
}

impl StorageStatement {
    /// Creates a Storage Statement.
    /// If `operated_by` is None, the registered_by will be used as the operated_by
    pub async fn create(
        data: String,
        stored_on: String,
        operated_by: Option<String>,
        registered_by: String,
        timestamp: Option<String>,
    ) -> Result<Self> {
        let type_ = "StorageRegistration".to_owned();

        let data = prepend_urn_cid(data.as_str())?;
        let stored_on = prepend_urn_cid(stored_on.as_str())?;

        let operated_by = match operated_by {
            Some(operated_by) => operated_by,
            None => registered_by.clone(),
        };

        let statement = Self {
            context: ig_common_context_link(),
            id: String::from("in-progress"),
            type_,
            registered_by,
            timestamp: format_timestamp(timestamp),
            data,
            stored_on,
            operated_by,
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

    use super::*;

    #[tokio::test]
    async fn generate_storage_statement_no_prefix() {
        let context = ig_common_context_link();
        let id = "urn:cid:bagb6qaq6ecj2fvdb73iohhtbghypdigq6guamxswyyzvnxcvfmfaitaxtqqq4";
        let type_ = "StorageRegistration";
        let data = "data_cid";
        let stored_on = "storage_cid";
        let operated_by = "did:key:zQ3shtdnadpYS81njBma5RqQMEAL3BenSJdCfZAu2Uj1ukwo9";
        let registered_by = operated_by;
        let timestamp = "2024-06-27T21:40:37Z";

        let s = StorageStatement::create(
            data.to_owned(),
            stored_on.to_owned(),
            Some(operated_by.to_owned()),
            registered_by.to_owned(),
            Some(timestamp.to_owned()),
        )
        .await
        .unwrap();

        assert_eq!(s.data, "urn:cid:data_cid", "Data match failed");
        assert_eq!(s.stored_on, "urn:cid:storage_cid", "StoredOn match failed");
        assert_eq!(s.operated_by, operated_by, "OperatedBy match failed");
        assert_eq!(s.registered_by, registered_by, "RegisteredBy match failed");

        assert_eq!(s.timestamp, timestamp, "Timestamp match failed");
        assert_eq!(s.context, context, "Context match failed");
        assert_eq!(s.id, id, "ID match failed");
        assert_eq!(s.type_, type_, "Type match failed");
    }

    #[tokio::test]
    async fn generate_storage_statement() {
        let context = ig_common_context_link();
        let id = "urn:cid:bagb6qaq6ecj2fvdb73iohhtbghypdigq6guamxswyyzvnxcvfmfaitaxtqqq4";
        let type_ = "StorageRegistration";
        let data = "urn:cid:data_cid";
        let stored_on = "urn:cid:storage_cid";
        let operated_by = "did:key:zQ3shtdnadpYS81njBma5RqQMEAL3BenSJdCfZAu2Uj1ukwo9";
        let registered_by = operated_by;
        let timestamp = "2024-06-27T21:40:37Z";

        let s = StorageStatement::create(
            data.to_owned(),
            stored_on.to_owned(),
            Some(operated_by.to_owned()),
            registered_by.to_owned(),
            Some(timestamp.to_owned()),
        )
        .await
        .unwrap();

        assert_eq!(s.data, data, "Data match failed");
        assert_eq!(s.stored_on, stored_on, "StoredOn match failed");
        assert_eq!(s.operated_by, operated_by, "OperatedBy match failed");
        assert_eq!(s.registered_by, registered_by, "RegisteredBy match failed");

        assert_eq!(s.timestamp, timestamp, "Timestamp match failed");
        assert_eq!(s.context, context, "Context match failed");
        assert_eq!(s.id, id, "ID match failed");
        assert_eq!(s.type_, type_, "Type match failed");
    }

    #[tokio::test]
    async fn generate_storage_statement_no_timestamp() {
        let context = ig_common_context_link();
        let type_ = "StorageRegistration";
        let data = "urn:cid:data_cid";
        let stored_on = "urn:cid:storage_cid";
        let operated_by = "did:key:zQ3shtdnadpYS81njBma5RqQMEAL3BenSJdCfZAu2Uj1ukwo9";
        let registered_by = operated_by;

        let s = StorageStatement::create(
            data.to_owned(),
            stored_on.to_owned(),
            Some(operated_by.to_owned()),
            registered_by.to_owned(),
            None,
        )
        .await
        .unwrap();

        let min_timestamp: DateTime<Utc> = "2024-06-27T14:00:00Z".parse().unwrap();
        let generated_timestamp: DateTime<Utc> = s.timestamp.parse().unwrap();
        assert!(generated_timestamp > min_timestamp);

        assert_eq!(s.data, data, "Data match failed");
        assert_eq!(s.stored_on, stored_on, "StoredOn match failed");
        assert_eq!(s.operated_by, operated_by, "OperatedBy match failed");
        assert_eq!(s.registered_by, registered_by, "RegisteredBy match failed");

        assert_eq!(s.context, context, "Context match failed");
        assert_eq!(s.type_, type_, "Type match failed");
    }
}
