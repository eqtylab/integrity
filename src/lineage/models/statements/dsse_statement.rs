use anyhow::Result;
use base64::engine::{general_purpose::STANDARD as BASE64, Engine};
use serde::{Deserialize, Serialize};

use super::{compute_cid, format_timestamp, get_jsonld_filename, StatementTrait};
use crate::{json_ld::ig_common_context_link, lineage::models::dsse::Envelope};

#[derive(Clone, Debug, Serialize, Deserialize, utoipa::ToSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DsseStatement {
    #[serde(rename = "@context")]
    pub context: String,
    #[serde(rename = "@id")]
    id: String,
    #[serde(rename = "@type")]
    pub type_: String,
    pub credential_dsse: Envelope,
    pub registered_by: String,
    pub timestamp: String,
}

impl StatementTrait for DsseStatement {
    fn get_id(&self) -> String {
        self.id.clone()
    }

    fn jsonld_filename(&self) -> String {
        get_jsonld_filename(self)
    }

    fn referenced_cids(&self) -> Vec<String> {
        let subject_urn_bytes = BASE64
            .decode(&self.credential_dsse.payload)
            .expect("Encountered corrupt hex encoding");
        let subject_urn_string = String::from_utf8_lossy(&subject_urn_bytes);
        let subject_cid = subject_urn_string
            .strip_prefix("urn:cid:")
            .unwrap_or(&subject_urn_string)
            .to_string();

        vec![subject_cid]
    }
}

impl DsseStatement {
    pub async fn create(
        envelope: Envelope,
        registered_by: String,
        timestamp: Option<String>,
    ) -> Result<Self> {
        let type_ = "CredentialRegistration".to_owned();

        let statement = Self {
            context: ig_common_context_link(),
            id: String::from("in-progress"),
            type_,
            credential_dsse: envelope,
            registered_by,
            timestamp: format_timestamp(timestamp),
        };

        // compute real CID and set
        let id = compute_cid(&statement).await?;
        let statement = Self { id, ..statement };

        Ok(statement)
    }
}
