use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use ssi::vc::{Credential, StringOrURI};

use super::{compute_cid, format_timestamp, get_jsonld_filename, StatementTrait};
use crate::json_ld::ig_common_context_link;

/// Records a W3C Verifiable Credential
///
/// This statement type stores verifiable credentials in W3C VC format,
/// providing cryptographically verifiable claims about subjects.
#[derive(Clone, Debug, Serialize, Deserialize, utoipa::ToSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VcStatement {
    /// JSON-LD context URL
    #[serde(rename = "@context")]
    pub context: String,
    /// Unique identifier for this statement
    #[serde(rename = "@id")]
    id: String,
    /// Statement type identifier
    #[serde(rename = "@type")]
    pub type_: String,
    /// The W3C Verifiable Credential
    #[schema(value_type = Value)]
    pub credential: Credential,
    /// DID of the entity that registered this statement
    pub registered_by: String,
    /// ISO 8601 timestamp of when the statement was created
    pub timestamp: String,
}

impl StatementTrait for VcStatement {
    fn get_id(&self) -> String {
        self.id.clone()
    }

    fn jsonld_filename(&self) -> String {
        get_jsonld_filename(self)
    }

    fn referenced_cids(&self) -> Vec<String> {
        let mut refs = vec![];

        // include credential subject
        match &self.credential.id {
            Some(StringOrURI::String(s)) => refs.push(s.clone()),
            Some(StringOrURI::URI(u)) => match u {
                ssi::vc::URI::String(s) => refs.push(s.clone()),
            },
            None => {}
        }

        // include credential evidence
        if let Some(evidence) = &self.credential.evidence {
            for ev in evidence {
                if let Some(props) = &ev.property_set {
                    for key in [
                        // `report` and `certificateChain` are used in everything but Azure
                        "report",
                        "certificateChain",
                        // `report` + the rest are used in TPM-based Azure attestation
                        "reportCertificateChain",
                        "tpmQuote",
                        "tpmQuoteSignature",
                        "tpmAKCertificate",
                        "tpmLog",
                        "azureBootLog",
                    ] {
                        if let Some(Value::String(id)) = props.get(key) {
                            refs.push(id.to_owned());
                        }
                    }
                }
            }
        }

        refs
    }
}

impl VcStatement {
    pub async fn create(
        credential: Credential,
        registered_by: String,
        timestamp: Option<String>,
    ) -> Result<Self> {
        let type_ = "CredentialRegistration".to_owned();

        let statement = Self {
            context: ig_common_context_link(),
            id: String::from("in-progress"),
            type_,
            credential,
            registered_by,
            timestamp: format_timestamp(timestamp),
        };

        // compute real CID and set
        let id = compute_cid(&statement).await?;
        let statement = Self { id, ..statement };

        Ok(statement)
    }
}
