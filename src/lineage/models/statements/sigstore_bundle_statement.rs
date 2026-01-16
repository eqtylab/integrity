use anyhow::Result;
use base64::engine::{general_purpose::STANDARD as BASE64, Engine};
use serde::{Deserialize, Serialize};

use super::{compute_cid, format_timestamp, get_jsonld_filename, StatementTrait};
use crate::{json_ld::ig_common_context_link, sigstore_bundle::SigstoreBundle};

#[derive(Clone, Debug, Serialize, Deserialize, utoipa::ToSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SigstoreBundleStatement {
    #[serde(rename = "@context")]
    pub context: String,
    #[serde(rename = "@id")]
    id: String,
    #[serde(rename = "@type")]
    pub type_: String,
    pub subject: String,
    pub sigstore_bundle: String,
    pub registered_by: String,
    pub timestamp: String,
}

impl StatementTrait for SigstoreBundleStatement {
    fn get_id(&self) -> String {
        self.id.clone()
    }

    fn jsonld_filename(&self) -> String {
        get_jsonld_filename(self)
    }

    fn referenced_cids(&self) -> Vec<String> {
        vec![]
    }
}

impl SigstoreBundleStatement {
    pub async fn create(
        subject: String,
        sigstore_bundle: &SigstoreBundle,
        registered_by: String,
        timestamp: Option<String>,
    ) -> Result<Self> {
        let type_ = "CredentialRegistration".to_owned();

        let sigstore_bundle = serde_jcs::to_string(sigstore_bundle)?;
        let sigstore_bundle = BASE64.encode(sigstore_bundle.as_bytes());

        let statement = Self {
            context: ig_common_context_link(),
            id: String::from("in-progress"),
            type_,
            subject,
            sigstore_bundle,
            registered_by,
            timestamp: format_timestamp(timestamp),
        };

        // compute real CID and set
        let id = compute_cid(&statement).await?;
        let statement = Self { id, ..statement };

        Ok(statement)
    }
}
