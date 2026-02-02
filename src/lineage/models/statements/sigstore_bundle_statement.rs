use anyhow::Result;
use base64::engine::{general_purpose::STANDARD as BASE64, Engine};
use serde::{Deserialize, Serialize};

use super::{compute_cid, format_timestamp, get_jsonld_filename, StatementTrait};
use crate::{json_ld::ig_common_context_link, sigstore_bundle::SigstoreBundle};

/// Records a Sigstore bundle as a credential
///
/// This statement type stores Sigstore bundles which contain signatures
/// and attestations from the Sigstore transparency log, providing
/// verifiable proof of software artifact authenticity.
#[derive(Clone, Debug, Serialize, Deserialize, utoipa::ToSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SigstoreBundleStatement {
    /// JSON-LD context URL
    #[serde(rename = "@context")]
    pub context: String,
    /// Unique identifier for this statement
    #[serde(rename = "@id")]
    id: String,
    /// Statement type identifier
    #[serde(rename = "@type")]
    pub type_: String,
    /// The subject that the bundle is about
    pub subject: String,
    /// Base64-encoded Sigstore bundle
    pub sigstore_bundle: String,
    /// DID of the entity that registered this statement
    pub registered_by: String,
    /// ISO 8601 timestamp of when the statement was created
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
    /// Creates a new Sigstore bundle statement for the given subject.
    ///
    /// # Arguments
    ///
    /// * `subject` - The subject that the bundle is about.
    /// * `sigstore_bundle` - Reference to the Sigstore bundle to include.
    /// * `registered_by` - DID of the entity registering this statement.
    /// * `timestamp` - Optional ISO 8601 timestamp; uses current time if not provided.
    ///
    /// # Returns
    ///
    /// A new `SigstoreBundleStatement` with a computed CID as its identifier.
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
