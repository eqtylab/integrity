use std::collections::HashMap;

use anyhow::Result;

use super::models;

/// A subject (artifact) that attestations are made about.
///
/// Subjects identify specific files, packages, or other artifacts
/// with their names and cryptographic digests for integrity verification.
#[derive(Debug, Clone)]
pub struct Subject {
    /// Name or identifier of the artifact
    pub name: String,
    /// Map of digest algorithm names to their digest values
    pub digest: HashMap<String, String>,
}

impl TryFrom<models::Subject> for Subject {
    type Error = anyhow::Error;

    fn try_from(subject: models::Subject) -> Result<Self> {
        let models::Subject { name, digest } = subject;

        Ok(Self { name, digest })
    }
}

impl From<Subject> for models::Subject {
    fn from(subject: Subject) -> Self {
        let Subject { name, digest } = subject;

        Self { name, digest }
    }
}
