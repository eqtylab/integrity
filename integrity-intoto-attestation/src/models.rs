use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Serializable representation of an in-toto statement.
///
/// Contains subjects (artifacts) and predicates (claims) that are
/// digitally signed to create attestations about software supply chain events.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Statement {
    /// The statement type identifier
    #[serde(rename = "_type")]
    pub type_: String,
    /// List of subjects (artifacts) this statement refers to
    pub subject: Vec<Subject>,
    /// The predicate (claim) being made about the subjects
    #[serde(flatten)]
    pub predicate: Predicate,
}

/// Represents a subject (artifact) in an in-toto statement.
///
/// Subjects identify the specific files, packages, or other artifacts
/// that the statement is making claims about, along with their cryptographic digests.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Subject {
    /// Name or identifier of the artifact
    pub name: String,
    /// Map of digest algorithm names to their digest values
    pub digest: HashMap<String, String>,
}

/// Represents a predicate (claim) in an in-toto statement.
///
/// Predicates describe what happened to the subjects, such as build information,
/// test results, or other supply chain metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Predicate {
    /// URI identifying the predicate type
    pub predicate_type: String,
    /// The predicate content as arbitrary JSON
    pub predicate: Value,
}
