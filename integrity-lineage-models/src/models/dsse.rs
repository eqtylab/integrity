use serde::{Deserialize, Serialize};

/// Serializable DSSE envelope for lineage data.
///
/// Contains a payload and one or more signatures for secure transmission
/// and storage of lineage statements.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Envelope {
    /// The type/format of the payload
    pub payload_type: String,
    /// The base64-encoded payload data
    pub payload: String,
    /// One or more digital signatures
    pub signatures: Vec<Signature>,
}

/// Serializable signature within a DSSE envelope.
///
/// Links a key identifier to its signature bytes for verification.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Signature {
    /// Key identifier used to create the signature
    pub keyid: String,
    /// The base64-encoded signature bytes
    pub sig: String,
}
