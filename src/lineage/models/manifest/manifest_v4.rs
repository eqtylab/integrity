use std::collections::HashMap;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::anchor::Anchor;
use crate::lineage::models::{
    graph::Graph, manifest::get_contexts_for_manifest, statements::Statement,
};

/// Version 4 of the lineage manifest format
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ManifestV4 {
    /// Version string identifying this manifest format
    pub version: String,
    /// JSON-LD contexts mapping context URLs to their definitions
    pub contexts: HashMap<String, Value>,
    /// Collection of lineage graphs contained in this manifest
    pub graphs: Vec<Graph>,
    /// Binary data blobs referenced by statements, keyed by CID
    pub blobs: HashMap<String, String>,
    /// Optional anchor points for statements on external systems
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anchors: Option<Vec<Anchor>>,
}

/// Generates a version 4 manifest from graphs and blobs
pub async fn generate_manifest_v4(
    include_context: bool,
    graphs: Vec<Graph>,
    blobs: HashMap<String, String>,
) -> Result<ManifestV4> {
    let contexts = if include_context {
        let graph_statements: Vec<Statement> = graphs
            .iter()
            .filter_map(|g| g.statements.clone())
            .flatten()
            .collect();
        get_contexts_for_manifest(&graph_statements)?
    } else {
        HashMap::new()
    };

    Ok(ManifestV4 {
        version: String::from("4"),
        contexts,
        graphs,
        blobs,
        anchors: None,
    })
}
