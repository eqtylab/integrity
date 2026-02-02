use serde::{Deserialize, Serialize};

/// Represents an anchor point for lineage statements on external systems
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct Anchor {
    /// List of statement identifiers or full statements being anchored
    pub statements: Vec<String>,
    /// Type of payload being anchored
    pub payload: Payload,
    /// Storage locations where the statements are anchored
    pub locations: Vec<Location>,
}

/// Defines what type of data is being anchored
#[derive(Debug, Clone, Copy, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(tag = "type")]
pub enum Payload {
    /// Full statement objects are being anchored
    Statement,
    /// Only statement identifiers are being anchored
    StatementId,
}

/// Represents a storage location where statements are anchored
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(tag = "type")]
pub enum Location {
    /// Hedera Consensus Service location
    #[schema(value_type = HcsLocation)]
    Hcs(HcsLocation),
    /// Hedera Token Service location
    #[schema(value_type = HtsLocation)]
    Hts(HtsLocation),
}

/// Hedera Consensus Service location details
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct HcsLocation {
    /// CAIP identifier for the network
    #[schema(value_type = String)]
    pub network: CaipIdentifier,
    /// Transaction identifier
    pub tx_id: String,
    /// Transaction hash
    pub tx_hash: String,
    /// Consensus timestamp of the transaction
    pub tx_consensus_timestamp: String,
    /// HCS topic identifier where the statement was anchored
    pub topic_id: String,
    /// Sequence number within the topic
    pub topic_sequence_number: u64,
    /// Optional URLs for accessing the anchored data
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub urls: Vec<String>,
}

/// Hedera Token Service location details
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct HtsLocation {
    /// CAIP identifier for the network
    #[schema(value_type = String)]
    pub network: CaipIdentifier,
    /// Transaction identifier
    pub tx_id: String,
    /// Transaction hash
    pub tx_hash: String,
    /// HTS token identifier where the statement was anchored
    pub token_id: String,
    /// Optional URLs for accessing the anchored data
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub urls: Vec<String>,
}

/// CAIP (Chain Agnostic Improvement Proposal) identifier for blockchain networks
pub type CaipIdentifier = String;
