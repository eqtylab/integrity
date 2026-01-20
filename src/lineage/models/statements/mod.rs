//! Lineage statement types and utilities
//!
//! This module contains all statement types used to record lineage events,
//! along with common utilities for statement creation and manipulation.

pub mod association_statement;
pub use association_statement::AssociationStatement;
pub mod computation_statement;
pub use computation_statement::ComputationStatement;
pub mod common;
pub mod data_statement;
pub use data_statement::DataStatement;
pub mod did_statement;
pub use did_statement::{
    DidStatement, DidStatementEqtyVCompAmdSevV1, DidStatementEqtyVCompAzureV1,
    DidStatementEqtyVCompCustomV1, DidStatementEqtyVCompDockerV1, DidStatementEqtyVCompIntelTdxV0,
    DidStatementRegular,
};
pub mod dsse_statement;
pub use dsse_statement::DsseStatement;
pub mod entity_statement;
pub use entity_statement::EntityStatement;
pub mod governance_statement;
pub use governance_statement::GovernanceStatement;
pub mod metadata_statement;
pub use metadata_statement::MetadataStatement;
pub mod sigstore_bundle_statement;
pub use sigstore_bundle_statement::SigstoreBundleStatement;
pub mod storage_statement;
pub use storage_statement::StorageStatement;
pub use vc_statement::VcStatement;
pub mod vc_statement;

use anyhow::{anyhow, bail, Result};
use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    cid::{blake3::blake3_cid, multicodec, prepend_urn_cid, prepend_urn_uuid, strip_urn_cid},
    json_ld::to_nquads::jsonld_to_nquads,
    nquads::canonicalize_nquads,
};

/// Represents a value that can be either a single item or an array of items
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, utoipa::ToSchema)]
#[serde(untagged)]
pub enum ValueOrArray<T> {
    /// A single value
    Value(T),
    /// An array of values
    Array(Vec<T>),
}

impl<T: ToString> ValueOrArray<T> {
    /// Converts a ValueOrArray to a Vec<String>
    pub fn to_vec_string(&self) -> Vec<String> {
        match self {
            ValueOrArray::Value(v) => vec![v.to_string()],
            ValueOrArray::Array(vec) => vec.iter().map(|v| v.to_string()).collect(),
        }
    }

    /// Converts a ValueOrArray to a comma-separated string
    pub fn to_csv_string(&self) -> String {
        match self {
            ValueOrArray::Value(v) => v.to_string(),
            ValueOrArray::Array(vec) => vec
                .iter()
                .map(|v| v.to_string())
                .collect::<Vec<_>>()
                .join(","),
        }
    }
}

/// Trait defining common operations for all lineage statement types
pub trait StatementTrait: Serialize {
    /// Returns the statement's unique identifier
    fn get_id(&self) -> String;

    /// Returns the statement's type as a string
    fn get_type_string(&self) -> Result<String> {
        let json = serde_json::to_value(self)?;
        let type_str = json
            .get("@type")
            .ok_or_else(|| anyhow!("'@type' not found in statement"))?
            .as_str()
            .ok_or_else(|| anyhow!("'@type' is not a string"))?
            .to_string();

        Ok(type_str)
    }

    /// Returns the statement ID without the 'urn:cid:' prefix
    fn get_id_no_prefix(&self) -> String {
        let cid = self.get_id();
        strip_urn_cid(&cid).to_string()
    }

    /// Returns the filename for the JSON-LD representation of this statement
    fn jsonld_filename(&self) -> String;

    /// Returns a list of CIDs referenced by this statement
    fn referenced_cids(&self) -> Vec<String>;
}

/// Removes the @id field from the statement and then computes the canonicalized cid
pub async fn compute_cid<S>(statement: &S) -> Result<String>
where
    S: StatementTrait + Serialize,
{
    let mut statement = serde_json::to_value(statement)?;

    let statement_stripped_id = {
        statement
            .as_object_mut()
            .ok_or_else(|| anyhow!("Failed to strip '@id' from integrity statement."))?
            .remove("@id");

        statement
    };

    let nquads = jsonld_to_nquads(statement_stripped_id, None).await?;
    let canon_nquads = canonicalize_nquads(nquads)?;

    let cid = blake3_cid(multicodec::RDFC_1_0, canon_nquads.as_bytes())?;
    let id = format!("urn:cid:{cid}");
    Ok(id)
}

/// Generates a JSON-LD filename from a statement's CID
fn get_jsonld_filename<S>(statement: &S) -> String
where
    S: StatementTrait,
{
    let cid = statement.get_id_no_prefix();
    format!("{}.jsonld", cid)
}

/// Formats a timestamp, using current time if none provided
fn format_timestamp(timestamp: Option<String>) -> String {
    timestamp.unwrap_or(Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true))
}

/// Removes any empty CIDs (trailing commas), and prepends 'urn:cid:' if needed
fn format_cids(cids: Vec<String>) -> Result<ValueOrArray<String>> {
    let cids: Vec<String> = cids
        .into_iter()
        .filter_map(|s| {
            if s.is_empty() {
                None
            } else {
                Some(prepend_urn_cid(s.as_str()))
            }
        })
        .collect::<Result<Vec<String>, _>>()?;

    match cids.as_slice() {
        [] => bail!("CID list must not be empty."),
        [single] => Ok(ValueOrArray::Value(single.clone())),
        _ => Ok(ValueOrArray::Array(cids)),
    }
}

/// Removes any empty UUIDs (trailing commas), and prepends 'urn:uuid:' if needed
fn format_uuids(uuids: Vec<String>) -> Result<ValueOrArray<String>> {
    let uuids: Vec<String> = uuids
        .into_iter()
        .filter_map(|s| {
            if s.is_empty() {
                None
            } else {
                Some(prepend_urn_uuid(s.as_str()))
            }
        })
        .collect::<Result<Vec<String>, _>>()?;

    match uuids.as_slice() {
        [] => bail!("CID list must not be empty."),
        [single] => Ok(ValueOrArray::Value(single.clone())),
        _ => Ok(ValueOrArray::Array(uuids)),
    }
}

/// Enum representing all possible lineage statement types
#[derive(Debug, Clone, utoipa::ToSchema, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum Statement {
    /// Records an association between two entities or artifacts
    AssociationRegistration(AssociationStatement),
    /// Records the storage of data on a specific system
    StorageRegistration(StorageStatement),
    /// Records metadata about an artifact or entity
    MetadataRegistration(MetadataStatement),
    /// Records a computational process with inputs and outputs
    ComputationRegistration(ComputationStatement),
    /// Records a verifiable credential
    CredentialRegistration(VcStatement),
    /// Records a DSSE-signed credential
    CredentialDsseRegistration(DsseStatement),
    /// Records a Sigstore bundle credential
    CredentialSigstoreBundleRegistration(SigstoreBundleStatement),
    /// Records a decentralized identifier (DID)
    DidRegistration(Box<DidStatement>),
    /// Records data artifact registration
    DataRegistration(DataStatement),
    /// Records entity registration
    EntityRegistration(EntityStatement),
    /// Records governance information
    GovernanceRegistration(GovernanceStatement),
}

impl Statement {
    /// Returns the DID of the entity that registered this statement
    pub fn get_registered_by(&self) -> &str {
        match self {
            Statement::AssociationRegistration(s) => &s.registered_by,
            Statement::StorageRegistration(s) => &s.registered_by,
            Statement::MetadataRegistration(s) => &s.registered_by,
            Statement::ComputationRegistration(s) => &s.registered_by,
            Statement::CredentialRegistration(s) => &s.registered_by,
            Statement::CredentialDsseRegistration(s) => &s.registered_by,
            Statement::CredentialSigstoreBundleRegistration(s) => &s.registered_by,
            Statement::DidRegistration(s) => s.get_registered_by(),
            Statement::DataRegistration(s) => &s.registered_by,
            Statement::EntityRegistration(s) => &s.registered_by,
            Statement::GovernanceRegistration(s) => &s.registered_by,
        }
    }
}

impl StatementTrait for Statement {
    fn get_id(&self) -> String {
        match self {
            Statement::AssociationRegistration(s) => s.get_id(),
            Statement::StorageRegistration(s) => s.get_id(),
            Statement::MetadataRegistration(s) => s.get_id(),
            Statement::ComputationRegistration(s) => s.get_id(),
            Statement::CredentialRegistration(s) => s.get_id(),
            Statement::CredentialDsseRegistration(s) => s.get_id(),
            Statement::CredentialSigstoreBundleRegistration(s) => s.get_id(),
            Statement::DidRegistration(s) => s.get_id(),
            Statement::DataRegistration(s) => s.get_id(),
            Statement::EntityRegistration(s) => s.get_id(),
            Statement::GovernanceRegistration(s) => s.get_id(),
        }
    }

    fn jsonld_filename(&self) -> String {
        match self {
            Statement::AssociationRegistration(s) => s.jsonld_filename(),
            Statement::StorageRegistration(s) => s.jsonld_filename(),
            Statement::MetadataRegistration(s) => s.jsonld_filename(),
            Statement::ComputationRegistration(s) => s.jsonld_filename(),
            Statement::CredentialRegistration(s) => s.jsonld_filename(),
            Statement::CredentialDsseRegistration(s) => s.jsonld_filename(),
            Statement::CredentialSigstoreBundleRegistration(s) => s.jsonld_filename(),
            Statement::DidRegistration(s) => s.jsonld_filename(),
            Statement::DataRegistration(s) => s.jsonld_filename(),
            Statement::EntityRegistration(s) => s.jsonld_filename(),
            Statement::GovernanceRegistration(s) => s.jsonld_filename(),
        }
    }

    fn referenced_cids(&self) -> Vec<String> {
        match self {
            Statement::AssociationRegistration(s) => s.referenced_cids(),
            Statement::StorageRegistration(s) => s.referenced_cids(),
            Statement::MetadataRegistration(s) => s.referenced_cids(),
            Statement::ComputationRegistration(s) => s.referenced_cids(),
            Statement::CredentialRegistration(s) => s.referenced_cids(),
            Statement::CredentialDsseRegistration(s) => s.referenced_cids(),
            Statement::CredentialSigstoreBundleRegistration(s) => s.referenced_cids(),
            Statement::DidRegistration(s) => s.referenced_cids(),
            Statement::DataRegistration(s) => s.referenced_cids(),
            Statement::EntityRegistration(s) => s.referenced_cids(),
            Statement::GovernanceRegistration(s) => s.referenced_cids(),
        }
    }
}

/// Helper function to get the @id field from a JSON Value Statement
pub fn extract_statement_id(statement: &Value) -> Result<String> {
    Ok(statement
        .get("@id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("Statement missing @id field"))?
        .to_string())
}

/// Helper function to get the @type field from a JSON Value Statement
pub fn extract_statement_type(statement: &Value) -> Result<String> {
    Ok(statement
        .get("@type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("Statement missing @id field"))?
        .to_string())
}
