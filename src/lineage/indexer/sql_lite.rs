use std::collections::HashMap;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde_json::{json, Value};
use sqlx::{Row, SqlitePool};

use crate::lineage::{
    indexer::{
        sql_indexer::{Filter, IStatementIdx},
        statement_filter::StatementFilter,
    },
    models::statements::{extract_statement_id, extract_statement_type, Statement, StatementTrait},
};

/// SQLite implementation of the statement indexer with filtering support.
///
/// Provides persistent storage for statements with a flexible filter DSL
/// for querying by type, attributes, and other criteria.
pub struct SqlLite {
    pool: SqlitePool,
}

impl SqlLite {
    /// Creates a new SQLite indexer and initializes the database schema.
    ///
    /// # Arguments
    /// * `database_url` - SQLite database connection string (e.g., "sqlite://path/to/db.sqlite")
    pub async fn new(database_url: &str) -> Result<Self> {
        let pool = SqlitePool::connect(database_url).await?;

        // Create the statements table if it doesn't exist
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS statements (
                statement_id TEXT PRIMARY KEY,
                statement_type TEXT NOT NULL,
                statement_data TEXT NOT NULL,
                attributes TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            "#,
        )
        .execute(&pool)
        .await?;

        Ok(Self { pool })
    }

    /// Updates the attributes for multiple statement IDs.
    pub async fn update_statements_attributes(
        &self,
        statement_ids: &Vec<String>,
        attributes: &Value,
    ) -> Result<()> {
        log::debug!(
            "Updating attributes for statements: {:?} with attributes: {}",
            statement_ids,
            attributes
        );

        if statement_ids.is_empty() {
            return Ok(());
        }

        // Build a query with IN clause for multiple IDs
        let placeholders = statement_ids
            .iter()
            .enumerate()
            .map(|(i, _)| format!("?{}", i + 1))
            .collect::<Vec<_>>()
            .join(",");

        let select_query = format!(
            "SELECT statement_id, attributes FROM statements WHERE statement_id IN ({})",
            placeholders
        );

        // Get current attributes for all matching statements
        let mut query = sqlx::query(&select_query);
        for id in statement_ids {
            query = query.bind(id);
        }

        let rows = query.fetch_all(&self.pool).await?;

        // For each statement, merge attributes and update
        for row in rows {
            let stmt_id: String = row.get("statement_id");
            let current_attrs_str: String = row.get("attributes");
            let mut current_attrs: Value = serde_json::from_str(&current_attrs_str)?;

            // Merge new attributes into current ones
            if let (Value::Object(ref mut current_map), Value::Object(new_map)) =
                (&mut current_attrs, attributes)
            {
                for (key, value) in new_map {
                    current_map.insert(key.clone(), value.clone());
                }
            }

            // Update this specific statement
            let merged_attrs_str = serde_json::to_string(&current_attrs)?;
            sqlx::query("UPDATE statements SET attributes = ?1 WHERE statement_id = ?2")
                .bind(&merged_attrs_str)
                .bind(&stmt_id)
                .execute(&self.pool)
                .await?;
        }

        Ok(())
    }

    /// Removes the attributes from the associted statement ids
    pub async fn remove_attributes(
        &self,
        statement_ids: &Vec<String>,
        attributes: &Value,
    ) -> Result<()> {
        if statement_ids.is_empty() {
            return Ok(());
        }

        // Build a query with IN clause for multiple IDs
        let placeholders = statement_ids
            .iter()
            .enumerate()
            .map(|(i, _)| format!("?{}", i + 1))
            .collect::<Vec<_>>()
            .join(",");

        let select_query = format!(
            "SELECT statement_id, attributes FROM statements WHERE statement_id IN ({})",
            placeholders
        );

        // Get current attributes for all matching statements
        let mut query = sqlx::query(&select_query);
        for id in statement_ids {
            query = query.bind(id);
        }

        let rows = query.fetch_all(&self.pool).await?;

        // For each statement, remove the matching attributes and update
        for row in rows {
            let stmt_id: String = row.get("statement_id");
            let current_attrs_str: String = row.get("attributes");
            let mut current_attrs: Value = serde_json::from_str(&current_attrs_str)?;

            // Remove the provided attributes from the record
            if let (Value::Object(ref mut current_map), Value::Object(attrs_to_remove)) =
                (&mut current_attrs, attributes)
            {
                current_map.retain(|key, _| !attrs_to_remove.contains_key(key));
            }

            // Update this specific statement
            let reduced_attrs_str = serde_json::to_string(&current_attrs)?;
            sqlx::query("UPDATE statements SET attributes = ?1 WHERE statement_id = ?2")
                .bind(&reduced_attrs_str)
                .bind(&stmt_id)
                .execute(&self.pool)
                .await?;
        }

        Ok(())
    }

    /// Delete the statements with the provided attributes
    pub async fn delete_statements(&self, filter_query: Option<&str>) -> Result<()> {
        let filter = filter_query.map(StatementFilter::parse_query).transpose()?;

        let mut query = "DELETE FROM statements".to_owned();
        let bind_values;

        if let Some(filter) = filter {
            let (where_clause, bv) = build_where_clause(&filter);

            query.push_str(&format!(" WHERE {where_clause}",));
            bind_values = bv;
        } else {
            bind_values = vec![];
        }

        let mut sqlx_query = sqlx::query(&query);
        for value in &bind_values {
            sqlx_query = sqlx_query.bind(value);
        }

        sqlx_query.execute(&self.pool).await?;

        Ok(())
    }
}

#[async_trait]
impl IStatementIdx for SqlLite {
    async fn register_statement(&self, statement: Statement, attributes: Value) -> Result<()> {
        // TODO: handle better
        let statement = serde_json::to_value(&statement)?;

        let id = extract_statement_id(&statement)?;

        let statement_type = extract_statement_type(&statement)?;

        let statement_data = serde_json::to_string(&statement)?;
        let attributes_data = serde_json::to_string(&attributes)?;

        log::debug!("Registering statement ID: {id}, attributes: {attributes_data}");

        sqlx::query(
            r#"
            INSERT OR REPLACE INTO statements
            (statement_id, statement_type, statement_data, attributes)
            VALUES (?1, ?2, ?3, ?4)
            "#,
        )
        .bind(&id)
        .bind(&statement_type)
        .bind(&statement_data)
        .bind(&attributes_data)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn retrieve_statements(
        &self,
        filter_query: Option<&str>,
    ) -> Result<(Vec<Statement>, HashMap<String, Value>)> {
        let filter = filter_query.map(StatementFilter::parse_query).transpose()?;

        let mut query = "SELECT statement_data, attributes FROM statements".to_owned();
        let bind_values;

        if let Some(filter) = filter {
            let (where_clause, bv) = build_where_clause(&filter);

            query.push_str(&format!(" WHERE {where_clause}",));
            bind_values = bv;
        } else {
            bind_values = vec![];
        }

        log::debug!("Executing query: {query} with bind values: {bind_values:?}");

        let mut sqlx_query = sqlx::query(&query);
        for value in &bind_values {
            sqlx_query = match value {
                Value::String(s) => sqlx_query.bind(s),
                Value::Number(n) => {
                    if let Some(i) = n.as_i64() {
                        sqlx_query.bind(i)
                    } else if let Some(f) = n.as_f64() {
                        sqlx_query.bind(f)
                    } else {
                        return Err(anyhow!("Unsupported number type in filter"));
                    }
                }
                _ => return Err(anyhow!("Unsupported value type in filter")),
            };
        }

        let rows = sqlx_query.fetch_all(&self.pool).await?;

        let mut statements = Vec::new();
        let mut attributes_map = HashMap::new();

        for row in rows {
            let statement_data: String = row.get("statement_data");
            let statement_value: Value = serde_json::from_str(&statement_data)?;
            let statement: Statement = serde_json::from_value(statement_value)?;
            let statement_id = statement.get_id();
            let attributes_str: String = row.get("attributes");
            let attributes: Value = serde_json::from_str(&attributes_str)?;

            statements.push(statement);
            attributes_map.insert(statement_id, attributes);
        }

        Ok((statements, attributes_map))
    }

    async fn get_unique_attributes(&self) -> Result<HashMap<String, Filter>> {
        let rows = sqlx::query(
            r#"
            SELECT DISTINCT
                json_each.key as attr_key,
                json_each.value as attr_value
            FROM statements,
                 json_each(statements.attributes)
            ORDER BY attr_key, attr_value
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        let mut attributes: HashMap<String, Vec<Value>> = HashMap::new();

        for row in rows {
            let key: String = row.get("attr_key");
            let value: Value = row.get("attr_value");

            attributes.entry(key).or_default().push(value);
        }

        let filters: HashMap<String, Filter> = attributes
            .into_iter()
            .map(|(key, values)| {
                let filter = Filter {
                    n: values.len(),
                    values: Some(values),
                };
                (key, filter)
            })
            .collect();

        Ok(filters)
    }

    async fn get_statement_by_id(&self, id: &str) -> Result<Option<Statement>> {
        let query = r#"
            SELECT statement FROM statements WHERE statement_id = ?1
        "#;

        let row = sqlx::query(query)
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;

        match row {
            Some(row) => {
                let statement: serde_json::Value = row.try_get("statement")?;
                let statement: Statement = serde_json::from_value(statement)?;
                Ok(Some(statement))
            }
            None => Ok(None),
        }
    }
}

fn build_where_clause(filter: &StatementFilter) -> (String, Vec<Value>) {
    let mut bind_values = Vec::new();
    let mut where_clause = build_indexed_where_clause(filter, &mut bind_values);

    // sqlite requires the bind values to be placeholded with '?' and then bound in the order they appear in the query
    // we've temporarily tagged the `?`s with their index (?1, ?2, etc) in the bind_values array
    // so we need to reorder the bind_values array to match the order of the `?`s in the query
    // and then remove the tags from the query
    //
    // this is a bit hacky but it works for now
    let mut ordered_bind_values = Vec::new();

    for (i, bind_value) in bind_values.iter().enumerate() {
        let indexed_placeholder = format!("?{}", i + 1);
        if let Some(pos) = where_clause.find(&indexed_placeholder) {
            where_clause.replace_range(pos..pos + indexed_placeholder.len(), "?");
            ordered_bind_values.push(bind_value.clone());
        }
    }

    (where_clause, ordered_bind_values)
}

// recursively build a WHERE clause from a StatementFilter
//
// this has indexed placeholders (?1, ?2, etc) for bind values
// to be replaced later with '?' and the bind values reordered accordingly
fn build_indexed_where_clause(filter: &StatementFilter, bind_values: &mut Vec<Value>) -> String {
    match filter {
        StatementFilter::StatementTypeEquals(type_) => {
            bind_values.push(json!(type_));
            format!("statement_type = ?{}", bind_values.len())
        }
        StatementFilter::AttributeEquals((k, v)) => {
            bind_values.push(v.clone());
            format!("json_extract(attributes, '$.{k}') = ?{}", bind_values.len())
        }
        StatementFilter::AttributeGreaterThan((k, n)) => {
            bind_values.push(Value::Number(n.clone()));
            format!("json_type(attributes, '$.{k}') IN ('integer','real') AND json_extract(attributes, '$.{k}') > ?{}", bind_values.len())
        }
        StatementFilter::AttributeLessThan((k, n)) => {
            bind_values.push(Value::Number(n.clone()));
            format!("json_type(attributes, '$.{k}') IN ('integer','real') AND json_extract(attributes, '$.{k}') < ?{}", bind_values.len())
        }
        StatementFilter::And(filters) => filters
            .iter()
            .map(|f| format!("({})", build_indexed_where_clause(f, bind_values)))
            .collect::<Vec<String>>()
            .join(" AND "),
        StatementFilter::Or(filters) => filters
            .iter()
            .map(|f| format!("({})", build_indexed_where_clause(f, bind_values)))
            .collect::<Vec<String>>()
            .join(" OR "),
        StatementFilter::Not(f) => {
            format!("NOT ({})", build_indexed_where_clause(f, bind_values))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::lineage::indexer::sql_indexer;

    async fn db() -> Arc<SqlLite> {
        Arc::new(SqlLite::new("sqlite::memory:").await.unwrap())
    }

    #[tokio::test]
    async fn test_statement_filter_type_equals() {
        sql_indexer::tests::test_statement_filter_type_equals(db().await).await;
    }

    #[tokio::test]
    async fn test_sqlite_statement_filter_attribute_equals() {
        sql_indexer::tests::test_statement_filter_attribute_equals(db().await).await;
    }

    #[tokio::test]
    async fn test_sqlite_statement_filter_attribute_greater_than() {
        sql_indexer::tests::test_statement_filter_attribute_greater_than(db().await).await;
    }

    #[tokio::test]
    async fn test_sqlite_statement_filter_attribute_less_than() {
        sql_indexer::tests::test_statement_filter_attribute_less_than(db().await).await;
    }

    #[tokio::test]
    async fn test_sqlite_statement_filter_and() {
        sql_indexer::tests::test_statement_filter_and(db().await).await;
    }

    #[tokio::test]
    async fn test_sqlite_statement_filter_or() {
        sql_indexer::tests::test_statement_filter_or(db().await).await;
    }

    #[tokio::test]
    async fn test_sqlite_statement_filter_not() {
        sql_indexer::tests::test_statement_filter_not(db().await).await;
    }

    #[tokio::test]
    async fn test_sqlite_statement_filter_dont_treat_strings_as_numbers() {
        sql_indexer::tests::test_statement_filter_dont_treat_strings_as_numbers(db().await).await;
    }

    #[tokio::test]
    async fn test_sqlite_statement_filter_dont_treat_numbers_as_strings() {
        sql_indexer::tests::test_statement_filter_dont_treat_numbers_as_strings(db().await).await;
    }
}
