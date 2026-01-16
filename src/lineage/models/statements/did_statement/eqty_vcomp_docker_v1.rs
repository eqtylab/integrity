use anyhow::Result;
use serde::{Deserialize, Serialize};

use super::super::{compute_cid, format_timestamp, get_jsonld_filename, StatementTrait};
use crate::{cid::prepend_urn_cid, json_ld::ig_common_context_link};

pub const VCOMP_TYPE_VALUE: &str = "EqtyVCompDockerV1";

#[derive(Clone, Debug, Serialize, Deserialize, utoipa::ToSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DidStatementEqtyVCompDockerV1 {
    #[serde(rename = "@context")]
    pub context: String,
    #[serde(rename = "@id")]
    id: String,
    #[serde(rename = "@type")]
    pub type_: String,
    pub did: String,
    pub vcomp: DidStatementEqtyVCompDockerV1VComp,
    pub registered_by: String,
    pub timestamp: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, utoipa::ToSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DidStatementEqtyVCompDockerV1VComp {
    #[serde(rename = "@type")]
    pub type_: String,
    pub image: Vec<DidStatementEqtyVCompDockerV1VCompImage>,
    pub compose: String,
    pub operated_by: String,
    pub executed_on: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, utoipa::ToSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DidStatementEqtyVCompDockerV1VCompImage {
    pub name: String,
    pub sha256: String,
}

impl StatementTrait for DidStatementEqtyVCompDockerV1 {
    fn get_id(&self) -> String {
        self.id.clone()
    }

    fn jsonld_filename(&self) -> String {
        get_jsonld_filename(self)
    }

    fn referenced_cids(&self) -> Vec<String> {
        vec![self.vcomp.compose.clone()]
    }
}

impl DidStatementEqtyVCompDockerV1 {
    /// Creates a new DidStatement_EqtyVCompDockerV1 object.
    /// `compose` cid will be prepended with `urn:cid:` if not already formatted with the prefix
    pub async fn create(
        did: String,
        image: Vec<(String, String)>,
        compose: String,
        operated_by: String,
        executed_on: String,
        registered_by: String,
        timestamp: Option<String>,
    ) -> Result<Self> {
        let image = image
            .into_iter()
            .map(|(name, sha256)| DidStatementEqtyVCompDockerV1VCompImage { name, sha256 })
            .collect();

        let compose = prepend_urn_cid(compose.as_str())?;

        let vcomp = DidStatementEqtyVCompDockerV1VComp {
            type_: VCOMP_TYPE_VALUE.to_owned(),
            image,
            compose,
            operated_by,
            executed_on,
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
