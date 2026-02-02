use anyhow::Result;
use serde::{Deserialize, Serialize};

use super::super::{compute_cid, format_timestamp, get_jsonld_filename, StatementTrait};
use crate::{cid::prepend_urn_cid, json_ld::ig_common_context_link};

/// Type identifier for Docker verified computing statements
pub const VCOMP_TYPE_VALUE: &str = "EqtyVCompDockerV1";

/// DID registration with Docker container attestation
///
/// This statement type registers a DID with proof of execution in a
/// specific Docker container environment.
#[derive(Clone, Debug, Serialize, Deserialize, utoipa::ToSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DidStatementEqtyVCompDockerV1 {
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
    pub vcomp: DidStatementEqtyVCompDockerV1VComp,
    /// DID of the entity that registered this statement
    pub registered_by: String,
    /// ISO 8601 timestamp of when the statement was created
    pub timestamp: String,
}

/// Docker container attestation data
#[derive(Clone, Debug, Serialize, Deserialize, utoipa::ToSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DidStatementEqtyVCompDockerV1VComp {
    /// Verified computing type identifier
    #[serde(rename = "@type")]
    pub type_: String,
    /// List of Docker images in the composition
    pub image: Vec<DidStatementEqtyVCompDockerV1VCompImage>,
    /// CID of the docker-compose file
    pub compose: String,
    /// DID of the entity operating the Docker environment
    pub operated_by: String,
    /// Identifier of the system where Docker is executed
    pub executed_on: String,
}

/// Docker image information with hash verification
#[derive(Clone, Debug, Serialize, Deserialize, utoipa::ToSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DidStatementEqtyVCompDockerV1VCompImage {
    /// Docker image name (e.g., "nginx:latest")
    pub name: String,
    /// SHA-256 hash of the image
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
