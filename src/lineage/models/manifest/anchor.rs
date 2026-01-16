use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct Anchor {
    pub statements: Vec<String>,
    pub payload: Payload,
    pub locations: Vec<Location>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(tag = "type")]
pub enum Payload {
    Statement,
    StatementId,
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(tag = "type")]
pub enum Location {
    #[schema(value_type = HcsLocation)]
    Hcs(HcsLocation),
    #[schema(value_type = HtsLocation)]
    Hts(HtsLocation),
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct HcsLocation {
    #[schema(value_type = String)]
    pub network: CaipIdentifier,
    pub tx_id: String,
    pub tx_hash: String,
    pub tx_consensus_timestamp: String,
    pub topic_id: String,
    pub topic_sequence_number: u64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub urls: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct HtsLocation {
    #[schema(value_type = String)]
    pub network: CaipIdentifier,
    pub tx_id: String,
    pub tx_hash: String,
    pub token_id: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub urls: Vec<String>,
}

pub type CaipIdentifier = String;
