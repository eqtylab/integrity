use serde_json::Value;
use sqlx::{FromRow, Row};

#[derive(Debug, sqlx::FromRow)]
pub struct AssociationRow {
    pub id: String,
    pub subject: String,
    pub association: String,
}

#[derive(Debug)]
pub struct StatementRow {
    pub statement: Value,
    pub metadata: Option<Value>,
    pub vc: Option<Value>,
    pub did: Option<Value>,
}

impl<'r, R> FromRow<'r, R> for StatementRow
where
    R: Row,
    for<'a> &'a str: sqlx::ColumnIndex<R>,
    for<'a> String: sqlx::Decode<'a, R::Database> + sqlx::Type<R::Database>,
    for<'a> Value: sqlx::Decode<'a, R::Database> + sqlx::Type<R::Database>,
{
    fn from_row(row: &'r R) -> Result<Self, sqlx::Error> {
        // Helper function to try JSON first, fall back to String parsing
        fn get_value<'r, R>(row: &'r R, column: &str) -> Result<Value, sqlx::Error>
        where
            R: Row,
            for<'a> &'a str: sqlx::ColumnIndex<R>,
            for<'a> String: sqlx::Decode<'a, R::Database> + sqlx::Type<R::Database>,
            for<'a> Value: sqlx::Decode<'a, R::Database> + sqlx::Type<R::Database>,
        {
            // Try JSON first (PostgreSQL)
            if let Ok(json_val) = row.try_get::<Value, _>(column) {
                Ok(json_val)
            } else {
                // Fall back to String (SQLite)
                let string_val: String = row.try_get(column)?;
                serde_json::from_str(&string_val).map_err(|e| sqlx::Error::Decode(Box::new(e)))
            }
        }

        // Helper function for optional columns
        fn get_optional_value<'r, R>(row: &'r R, column: &str) -> Result<Option<Value>, sqlx::Error>
        where
            R: Row,
            for<'a> &'a str: sqlx::ColumnIndex<R>,
            for<'a> String: sqlx::Decode<'a, R::Database> + sqlx::Type<R::Database>,
            for<'a> Value: sqlx::Decode<'a, R::Database> + sqlx::Type<R::Database>,
        {
            let c = row.try_column(column);
            if c.is_err() {
                return Ok(None);
            }

            // Try JSON first (PostgreSQL)
            if let Ok(json_val) = row.try_get::<Option<Value>, _>(column) {
                Ok(json_val)
            } else {
                // Fall back to String (SQLite)
                match row.try_get::<Option<String>, _>(column)? {
                    Some(string_val) => {
                        log::trace!("opt txt column {column}");
                        let value = serde_json::from_str(&string_val)
                            .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;
                        Ok(Some(value))
                    }
                    None => Ok(None),
                }
            }
        }

        Ok(StatementRow {
            statement: get_value(row, "statement")?,
            metadata: get_optional_value(row, "metadata")?,
            vc: get_optional_value(row, "vc")?,
            did: get_optional_value(row, "did")?,
        })
    }
}
