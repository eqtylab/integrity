use serde::{Deserialize, Serialize};
use sqlx::{postgres::PgRow, sqlite::SqliteRow, FromRow, Row};
use uuid::Uuid;

use crate::lineage::models::statements::Statement;

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema, FromRow)]
pub struct Graph {
    pub name: String,
    #[sqlx(rename = "graph_id")]
    pub id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[sqlx(rename = "parent_id")]
    pub parent: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[sqlx(skip)]
    pub statements: Option<Vec<Statement>>,
}

impl From<SqliteRow> for Graph {
    fn from(row: SqliteRow) -> Self {
        let id: String = row.get("graph_id");
        let parent_id: String = row.get("parent_id");
        let name: String = row.get("name");

        // If the parent_id None, sqlite still returns an empty string
        let mut parent = None;
        if !parent_id.is_empty() {
            parent = Some(parent_id);
        }

        log::debug!("Creating Graph from {id}-{name} (parent:{parent:?})");
        Self {
            name,
            id: Uuid::parse_str(&id).expect("Invalid UUID"),
            parent: parent.map(|p| Uuid::parse_str(&p).expect("Invalid parent UUID")),
            statements: None,
        }
    }
}

impl From<PgRow> for Graph {
    fn from(row: PgRow) -> Self {
        log::debug!("Converting PgRow");
        let id: Uuid = row.get("graph_id");
        let parent: Option<Uuid> = row.get("parent_id");
        let name: String = row.get("name");

        log::debug!("Creating Graph from {id}-{name} (parent:{parent:?})");
        Self {
            name,
            id,
            parent,
            statements: None,
        }
    }
}
