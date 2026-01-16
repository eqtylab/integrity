use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::super::{compute_cid, format_timestamp, get_jsonld_filename, StatementTrait};
use crate::json_ld::ig_common_context_link;

pub const VCOMP_TYPE_VALUE: &str = "EqtyVCompCustomV1";

#[derive(Clone, Debug, Serialize, Deserialize, utoipa::ToSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DidStatementEqtyVCompCustomV1 {
    #[serde(rename = "@context")]
    pub context: String,
    #[serde(rename = "@id")]
    id: String,
    #[serde(rename = "@type")]
    pub type_: String,
    pub did: String,
    pub vcomp: DidStatementEqtyVCompCustomV1VComp,
    pub registered_by: String,
    pub timestamp: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, utoipa::ToSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DidStatementEqtyVCompCustomV1VComp {
    #[serde(rename = "@type")]
    pub type_: String,
    pub value: Value,
}

impl StatementTrait for DidStatementEqtyVCompCustomV1 {
    fn get_id(&self) -> String {
        self.id.clone()
    }

    fn jsonld_filename(&self) -> String {
        get_jsonld_filename(self)
    }

    fn referenced_cids(&self) -> Vec<String> {
        fn recursive_get_cids_from_value(value: &Value) -> Vec<String> {
            let mut cids = Vec::new();

            match value {
                Value::String(s) => {
                    if s.starts_with("urn:cid:") {
                        cids.push(s.clone());
                    }
                }
                Value::Array(arr) => {
                    for item in arr {
                        cids.extend(recursive_get_cids_from_value(item));
                    }
                }
                Value::Object(map) => {
                    for (_k, v) in map {
                        cids.extend(recursive_get_cids_from_value(v));
                    }
                }
                _ => {}
            }

            cids
        }

        recursive_get_cids_from_value(&self.vcomp.value)
    }
}

impl DidStatementEqtyVCompCustomV1 {
    /// Creates a new DidStatement_EqtyVCompCustomV1 object.
    pub async fn create(
        did: String,
        value: Value,
        registered_by: String,
        timestamp: Option<String>,
    ) -> Result<Self> {
        let vcomp = DidStatementEqtyVCompCustomV1VComp {
            type_: VCOMP_TYPE_VALUE.to_owned(),
            value,
        };

        let statement = Self {
            context: ig_common_context_link(),
            id: String::from("in-progress"),
            type_: "DidRegistration".to_owned(),
            did,
            vcomp,
            registered_by,
            timestamp: format_timestamp(timestamp),
        };

        // compute real CID and set
        let id = compute_cid(&statement).await?;
        let statement = Self { id, ..statement };

        Ok(statement)
    }
}
