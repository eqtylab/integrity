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
    #[serde(rename = "_type")]
    pub type_: String,
    pub subject: Vec<Subject>,
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
    pub name: String,
    pub digest: HashMap<String, String>,
}

/// Represents a predicate (claim) in an in-toto statement.
///
/// Predicates describe what happened to the subjects, such as build information,
/// test results, or other supply chain metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Predicate {
    pub predicate_type: String,
    pub predicate: Value,
}
