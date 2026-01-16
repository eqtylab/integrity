use anyhow::Result;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::{compute_cid, format_timestamp, get_jsonld_filename, StatementTrait};
use crate::json_ld::ig_common_context_link;

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GovernanceStatement {
    #[serde(rename = "@context")]
    pub context: String,
    #[serde(rename = "@id")]
    id: String,
    #[serde(rename = "@type")]
    pub type_: String,
    pub registered_by: String,
    pub timestamp: String,
    pub subject: String,
    pub document: String,
}

impl StatementTrait for GovernanceStatement {
    fn get_id(&self) -> String {
        self.id.clone()
    }

    fn jsonld_filename(&self) -> String {
        get_jsonld_filename(self)
    }

    fn referenced_cids(&self) -> Vec<String> {
        vec![self.subject.clone(), self.document.clone()]
    }
}

impl GovernanceStatement {
    /// Creates a new GovernanceStatement object.
    pub async fn create(
        subject: String,
        document: String,
        registered_by: String,
        timestamp: Option<String>,
    ) -> Result<Self> {
        let type_ = "GovernanceRegistration".to_owned();

        let statement = Self {
            context: ig_common_context_link(),
            id: String::from("in-progress"),
            type_,
            registered_by,
            timestamp: format_timestamp(timestamp),
            subject,
            document,
        };

        // compute real CID and set
        let id = compute_cid(&statement).await?;
        let statement = Self { id, ..statement };

        Ok(statement)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn generate_governance_statement_single_cid() {
        let id = "urn:cid:bagb6qaq6eabm775wexlrjbf74n4dnw6oykw4qoj2zliqbt3gwgmuh64tsxtug";
        let context = ig_common_context_link();
        let type_ = "GovernanceRegistration";
        let subject = "urn:cid:subject_cid";
        let document = "urn:cid:document_cid";
        let registered_by = "did:key:zQ3shtdnadpYS81njBma5RqQMEAL3BenSJdCfZAu2Uj1ukwo9";
        let timestamp = "2024-06-27T21:40:37Z";

        let s = GovernanceStatement::create(
            subject.to_owned(),
            document.to_owned(),
            registered_by.to_owned(),
            Some(timestamp.to_owned()),
        )
        .await
        .expect("Failed to create governance statement");

        assert_eq!(s.subject, subject, "subject match failed");
        assert_eq!(s.document, document, "document match failed");
        assert_eq!(s.registered_by, registered_by, "RegisteredBy match failed");

        assert_eq!(s.id, id, "ID match failed");
        assert_eq!(s.timestamp, timestamp, "Timestamp match failed");
        assert_eq!(s.context, context, "Context match failed");
        assert_eq!(s.type_, type_, "Type match failed");
    }
}
