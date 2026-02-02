use anyhow::Result;

use super::{models, predicate::Predicate, subject::Subject};

/// An in-toto statement representing an attestation about software artifacts.
///
/// Contains one or more subjects (artifacts) and a predicate (claim) about them,
/// forming the core structure for supply chain attestations.
#[derive(Debug, Clone)]
pub struct Statement {
    /// List of subjects (artifacts) this statement refers to
    pub subject: Vec<Subject>,
    /// The predicate (claim) being made about the subjects
    pub predicate: Predicate,
}

impl Statement {
    /// Converts the statement into a JSON string representation.
    ///
    /// # Returns
    /// * `Result<String>` - JSON string of the statement, or error if serialization fails
    pub fn into_json_string(self) -> Result<String> {
        let statement = models::Statement::from(self);
        let s = serde_json::to_string(&statement)?;

        Ok(s)
    }
}

impl TryFrom<models::Statement> for Statement {
    type Error = anyhow::Error;

    fn try_from(statement: models::Statement) -> Result<Self> {
        let models::Statement {
            subject, predicate, ..
        } = statement;

        let subject = subject
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>>>()?;
        let predicate = predicate.try_into()?;

        Ok(Self { subject, predicate })
    }
}

impl From<Statement> for models::Statement {
    fn from(statement: Statement) -> Self {
        let Statement { subject, predicate } = statement;

        let subject = subject.into_iter().map(Into::into).collect();
        let predicate = predicate.into();

        Self {
            type_: "https://in-toto.io/Statement/v1".to_owned(),
            subject,
            predicate,
        }
    }
}
