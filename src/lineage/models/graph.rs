use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::lineage::models::statements::Statement;

/// A graph structure for organizing related statements hierarchically.
///
/// Graphs group statements together with optional parent-child relationships,
/// enabling versioning and organizational structure for lineage data.
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct Graph {
    /// Human-readable name for this graph
    pub name: String,
    /// Unique identifier for this graph
    pub id: Uuid,
    /// Optional parent graph ID for hierarchical organization
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<Uuid>,
    /// Statements contained in this graph (populated on retrieval)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub statements: Option<Vec<Statement>>,
}
