use anyhow::Result;
use serde::{Deserialize, Serialize};

use super::super::{compute_cid, format_timestamp, get_jsonld_filename, StatementTrait};
use crate::json_ld::ig_common_context_link;

#[derive(Clone, Debug, Serialize, Deserialize, utoipa::ToSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DidStatementRegular {
    #[serde(rename = "@context")]
    pub context: String,
    #[serde(rename = "@id")]
    id: String,
    #[serde(rename = "@type")]
    pub type_: String,
    pub did: String,
    pub registered_by: String,
    pub timestamp: String,
}

impl StatementTrait for DidStatementRegular {
    fn get_id(&self) -> String {
        self.id.clone()
    }

    fn jsonld_filename(&self) -> String {
        get_jsonld_filename(self)
    }

    fn referenced_cids(&self) -> Vec<String> {
        Vec::new()
    }
}

impl DidStatementRegular {
    /// Creates a new DidStatementRegular object.
    pub async fn create(
        did: String,
        registered_by: String,
        timestamp: Option<String>,
    ) -> Result<Self> {
        let statement = Self {
            context: ig_common_context_link(),
            id: String::from("in-progress"),
            type_: "DidRegistration".to_owned(),
            did,
            registered_by,
            timestamp: format_timestamp(timestamp),
        };

        // compute real CID and set
        let id = compute_cid(&statement).await?;
        let statement = Self { id, ..statement };

        Ok(statement)
    }
}
