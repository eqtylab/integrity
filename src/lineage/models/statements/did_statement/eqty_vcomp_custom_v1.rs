use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::super::{compute_cid, format_timestamp, get_jsonld_filename, StatementTrait};
use crate::json_ld::ig_common_context_link;

/// Type identifier for custom verified computing statements
pub const VCOMP_TYPE_VALUE: &str = "EqtyVCompCustomV1";

/// DID registration with custom verified computing attestation
///
/// This statement type registers a DID with a custom attestation format,
/// allowing for flexible verification data that doesn't fit other categories.
#[derive(Clone, Debug, Serialize, Deserialize, utoipa::ToSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DidStatementEqtyVCompCustomV1 {
    /// JSON-LD context URL
    #[serde(rename = "@context")]
    pub context: String,
    /// Unique identifier for this statement
    #[serde(rename = "@id")]
    id: String,
    /// Statement type identifier
    #[serde(rename = "@type")]
    pub type_: String,
    /// The DID being registered
    pub did: String,
    /// Verified computing attestation data
    pub vcomp: DidStatementEqtyVCompCustomV1VComp,
    /// DID of the entity that registered this statement
    pub registered_by: String,
    /// ISO 8601 timestamp of when the statement was created
    pub timestamp: String,
}

/// Custom verified computing attestation data
#[derive(Clone, Debug, Serialize, Deserialize, utoipa::ToSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DidStatementEqtyVCompCustomV1VComp {
    /// Verified computing type identifier
    #[serde(rename = "@type")]
    pub type_: String,
    /// Arbitrary JSON value containing custom attestation data
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
