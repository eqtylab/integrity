use std::collections::{HashMap, HashSet};

use anyhow::Result;
use async_trait::async_trait;
use sqlx::{sqlite::SqliteRow, SqlitePool};
use uuid::Uuid;

use crate::lineage::{
    graph_indexer::{row_types::AssociationRow, sql_indexer::IStatementIdx},
    models::{
        graph::Graph,
        statements::{Statement, StatementTrait},
    },
};

/// SQLite implementation of the graph-based statement indexer.
///
/// Provides persistent storage for statements organized in graphs
/// with support for hierarchical relationships and queries.
pub struct Sqlite {
    pool: SqlitePool,
}

impl Sqlite {
    // Use the generic function from sql_indexer
    fn parse_statement_rows(rows: Vec<SqliteRow>) -> Result<HashMap<String, Statement>> {
        super::sql_indexer::rows_to_statements(rows)
    }

    /// Initializes the database schema by creating all necessary tables and indexes.
    pub async fn init(&self) -> Result<()> {
        let comp_tables = r#"
            CREATE TABLE IF NOT EXISTS computation_statements (
                id TEXT PRIMARY KEY,
                statement TEXT NOT NULL,
                registered_by TEXT NOT NULL
            );
        "#;
        sqlx::query(comp_tables).execute(&self.pool).await?;

        let data_tables = r#"
            CREATE TABLE IF NOT EXISTS data_statements (
                id TEXT PRIMARY KEY,
                statement TEXT NOT NULL,
                registered_by TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS data_statement_subjects (
                statement_id TEXT NOT NULL,
                subject TEXT NOT NULL,
                PRIMARY KEY (statement_id, subject),
                FOREIGN KEY (statement_id) REFERENCES data_statements(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_data_statement_subjects_subject ON data_statement_subjects(subject);
        "#;
        sqlx::query(data_tables).execute(&self.pool).await?;

        let metadata_table = r#"
            CREATE TABLE IF NOT EXISTS metadata_statements (
                id TEXT PRIMARY KEY,
                statement TEXT NOT NULL,
                registered_by TEXT NOT NULL,
                subject TEXT NOT NULL
            );
        "#;
        sqlx::query(metadata_table).execute(&self.pool).await?;

        let storage_table = r#"
            CREATE TABLE IF NOT EXISTS storage_statements (
                id TEXT PRIMARY KEY,
                statement TEXT NOT NULL,
                registered_by TEXT NOT NULL,
                data TEXT NOT NULL
            );
        "#;
        sqlx::query(storage_table).execute(&self.pool).await?;

        let entity_table = r#"
            CREATE TABLE IF NOT EXISTS entity_statements (
                id TEXT PRIMARY KEY,
                statement TEXT NOT NULL,
                registered_by TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS entity_statement_subjects (
                statement_id TEXT NOT NULL,
                entity TEXT NOT NULL,
                PRIMARY KEY (statement_id, entity),
                FOREIGN KEY (statement_id) REFERENCES entity_statements(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_entity_statement_subjects_subject ON entity_statement_subjects(entity);
        "#;
        sqlx::query(entity_table).execute(&self.pool).await?;

        let association_table = r#"
            CREATE TABLE IF NOT EXISTS association_statements (
                id TEXT PRIMARY KEY,
                statement TEXT NOT NULL,
                registered_by TEXT NOT NULL,
                subject TEXT NOT NULL,
                association TEXT NOT NULL
            );
        "#;
        sqlx::query(association_table).execute(&self.pool).await?;

        let graph_tables = r#"
            CREATE TABLE IF NOT EXISTS statement_graph_link (
                statement_id TEXT NOT NULL,
                graph_id TEXT NOT NULL,
                PRIMARY KEY (statement_id, graph_id),
                FOREIGN KEY (graph_id) REFERENCES graphs(graph_id)
            );

            CREATE TABLE IF NOT EXISTS graphs (
                graph_id TEXT PRIMARY KEY,
                name TEXT,
                parent_id TEXT,
                FOREIGN KEY (parent_id) REFERENCES graphs(graph_id)
            );
        "#;
        sqlx::query(graph_tables).execute(&self.pool).await?;

        let sigstore_table = r#"
            CREATE TABLE IF NOT EXISTS sigstore_statements (
                id TEXT PRIMARY KEY,
                statement TEXT NOT NULL,
                registered_by TEXT NOT NULL
            );
        "#;
        sqlx::query(sigstore_table).execute(&self.pool).await?;

        let credential_table = r#"
            CREATE TABLE IF NOT EXISTS credential_statements (
                id TEXT PRIMARY KEY,
                statement TEXT NOT NULL,
                registered_by TEXT NOT NULL,
                credential_subject TEXT NOT NULL
            );
        "#;
        sqlx::query(credential_table).execute(&self.pool).await?;

        let dsse_table = r#"
            CREATE TABLE IF NOT EXISTS dsse_statements (
                id TEXT PRIMARY KEY,
                statement TEXT NOT NULL,
                registered_by TEXT NOT NULL
            );
        "#;
        sqlx::query(dsse_table).execute(&self.pool).await?;

        let did_table = r#"
            CREATE TABLE IF NOT EXISTS did_statements (
                id TEXT PRIMARY KEY,
                statement TEXT NOT NULL,
                registered_by TEXT NOT NULL,
                type TEXT NOT NULL,
                did TEXT NOT NULL
            );
        "#;
        sqlx::query(did_table).execute(&self.pool).await?;

        let governance_table = r#"
            CREATE TABLE IF NOT EXISTS governance_statements (
                id TEXT PRIMARY KEY,
                statement TEXT NOT NULL,
                registered_by TEXT NOT NULL,
                subject TEXT NOT NULL,
                document TEXT NOT NULL
            );
        "#;
        sqlx::query(governance_table).execute(&self.pool).await?;

        Ok(())
    }

    /// Creates a new SQLite indexer connected to the database at the given URL.
    ///
    /// # Arguments
    /// * `database_url` - SQLite database connection string (e.g., "sqlite://path/to/db.sqlite")
    pub async fn new(database_url: &str) -> Result<Self> {
        let pool = SqlitePool::connect(database_url).await?;

        Ok(Self { pool })
    }

    /// Helper to handle optionally associating a statement with a graph_id
    async fn opt_associate_statement_to_graph(
        &self,
        statement_id: &str,
        graph_id: Option<&Uuid>,
    ) -> Result<()> {
        if let Some(graph_id) = graph_id {
            log::debug!("Registering '{statement_id}' under graph {graph_id:?}");
            self.associate_statement_to_graph(statement_id, graph_id)
                .await?;
        }
        Ok(())
    }

    /// Only used for Comp, Data, Metadata, Storage & Association
    async fn register_graph_statement(
        &self,
        statement: &Statement,
        graph_id: Option<&Uuid>,
    ) -> Result<()> {
        match statement {
            Statement::ComputationRegistration(s) => {
                let statement = serde_json::to_value(statement)?;
                let id = s.get_id();
                let statement_data = serde_json::to_string(&statement)?;
                log::debug!("Registering computation '{id}'");
                sqlx::query(
                    r#"
                    INSERT OR IGNORE INTO computation_statements
                    (id, statement, registered_by) VALUES (?1, ?2, ?3)
                "#,
                )
                .bind(&id)
                .bind(&statement_data)
                .bind(&s.registered_by)
                .execute(&self.pool)
                .await?;

                self.opt_associate_statement_to_graph(&id, graph_id).await
            }
            Statement::DataRegistration(s) => {
                let statement = serde_json::to_value(statement)?;
                let id = s.get_id();
                let statement_data = serde_json::to_string(&statement)?;
                log::debug!("Registering data '{id}'");
                sqlx::query(
                    r#"
                    INSERT OR IGNORE INTO data_statements
                    (id, statement, registered_by) VALUES (?1, ?2, ?3)
                "#,
                )
                .bind(&id)
                .bind(&statement_data)
                .bind(&s.registered_by)
                .execute(&self.pool)
                .await?;

                self.opt_associate_statement_to_graph(&id, graph_id).await?;

                for data_item in s.data.to_vec_string() {
                    sqlx::query(
                        r#"
                      INSERT OR IGNORE INTO data_statement_subjects
                      (statement_id, subject) VALUES (?1, ?2)
                    "#,
                    )
                    .bind(&id)
                    .bind(data_item)
                    .execute(&self.pool)
                    .await?;
                }
                Ok(())
            }
            Statement::MetadataRegistration(s) => {
                let statement = serde_json::to_value(statement)?;
                let id = s.get_id();
                let statement_data = serde_json::to_string(&statement)?;
                log::debug!("Registering metadata '{id}'");
                sqlx::query(
                    r#"
                    INSERT OR IGNORE INTO metadata_statements
                    (id, statement, registered_by, subject) VALUES (?1, ?2, ?3, ?4)
                "#,
                )
                .bind(&id)
                .bind(&statement_data)
                .bind(&s.registered_by)
                .bind(&s.subject)
                .execute(&self.pool)
                .await?;

                self.opt_associate_statement_to_graph(&id, graph_id).await
            }
            Statement::StorageRegistration(s) => {
                let statement = serde_json::to_value(statement)?;
                let id = s.get_id();
                let statement_data = serde_json::to_string(&statement)?;
                log::debug!("Registering storage '{id}'");
                sqlx::query(
                    r#"
                    INSERT OR IGNORE INTO storage_statements
                    (id, statement, registered_by, data) VALUES (?1, ?2, ?3, ?4)
                "#,
                )
                .bind(&id)
                .bind(&statement_data)
                .bind(&s.registered_by)
                .bind(&s.data)
                .execute(&self.pool)
                .await?;

                self.opt_associate_statement_to_graph(&id, graph_id).await
            }
            Statement::EntityRegistration(s) => {
                let statement = serde_json::to_value(statement)?;
                let id = s.get_id();
                let statement_data = serde_json::to_string(&statement)?;
                log::debug!("Registering entity '{id}'");
                sqlx::query(
                    r#"
                    INSERT OR IGNORE INTO entity_statements
                    (id, statement, registered_by) VALUES (?1, ?2, ?3)
                "#,
                )
                .bind(&id)
                .bind(&statement_data)
                .bind(&s.registered_by)
                .execute(&self.pool)
                .await?;

                self.opt_associate_statement_to_graph(&id, graph_id).await?;

                for entity in s.entity.to_vec_string() {
                    sqlx::query(
                        r#"
                      INSERT OR IGNORE INTO entity_statement_subjects
                      (statement_id, entity) VALUES (?1, ?2)
                    "#,
                    )
                    .bind(&id)
                    .bind(entity)
                    .execute(&self.pool)
                    .await?;
                }

                Ok(())
            }
            Statement::AssociationRegistration(s) => {
                let statement = serde_json::to_value(statement)?;
                let id = s.get_id();
                let statement_data = serde_json::to_string(&statement)?;
                log::debug!("Registering association '{id}'");
                sqlx::query(
                    r#"
                    INSERT OR IGNORE INTO association_statements
                    (id, statement, registered_by, subject, association) VALUES (?1, ?2, ?3, ?4, ?5)
                "#,
                )
                .bind(&id)
                .bind(&statement_data)
                .bind(&s.registered_by)
                .bind(&s.subject)
                .bind(&s.association)
                .execute(&self.pool)
                .await?;

                self.opt_associate_statement_to_graph(&id, graph_id).await
            }
            Statement::CredentialSigstoreBundleRegistration(_)
            | Statement::DidRegistration(_)
            | Statement::GovernanceRegistration(_)
            | Statement::CredentialDsseRegistration(_)
            | Statement::CredentialRegistration(_) => {
                log::error!(
                    "Attempted to register a non-graph specific statement '{}' to a graph",
                    statement.get_type_string().unwrap_or("UNKNOWN".to_owned())
                );
                Ok(())
            }
        }
    }

    async fn register_global_statement(&self, statement: &Statement) -> Result<()> {
        match statement {
            Statement::CredentialSigstoreBundleRegistration(s) => {
                let statement = serde_json::to_value(statement)?;
                let id = s.get_id();
                let statement_data = serde_json::to_string(&statement)?;
                log::debug!("Registering sigstore bundle '{id}'");
                sqlx::query(
                    r#"
                    INSERT OR IGNORE INTO sigstore_statements
                    (id, statement, registered_by) VALUES (?1, ?2, ?3)
                "#,
                )
                .bind(&id)
                .bind(&statement_data)
                .bind(&s.registered_by)
                .execute(&self.pool)
                .await?;

                Ok(())
            }
            Statement::CredentialRegistration(s) => {
                let statement = serde_json::to_value(statement)?;
                let id = s.get_id();
                let statement_data = serde_json::to_string(&statement)?;
                log::debug!("Registering credential '{id}'");
                let subject = s
                    .credential
                    .credential_subject
                    .first()
                    .and_then(|s| s.id.as_ref())
                    .map(|id| id.to_string())
                    .unwrap_or_default();

                sqlx::query(
                    r#"
                    INSERT OR IGNORE INTO credential_statements
                    (id, statement, registered_by, credential_subject) VALUES (?1, ?2, ?3, ?4)
                "#,
                )
                .bind(&id)
                .bind(&statement_data)
                .bind(&s.registered_by)
                .bind(&subject)
                .execute(&self.pool)
                .await?;

                Ok(())
            }
            Statement::CredentialDsseRegistration(s) => {
                let statement = serde_json::to_value(statement)?;
                let id = s.get_id();
                let statement_data = serde_json::to_string(&statement)?;
                log::debug!("Registering dsse '{id}'");
                sqlx::query(
                    r#"
                    INSERT OR IGNORE INTO dsse_statements
                    (id, statement, registered_by) VALUES (?1, ?2, ?3)
                "#,
                )
                .bind(&id)
                .bind(&statement_data)
                .bind(&s.registered_by)
                .execute(&self.pool)
                .await?;

                Ok(())
            }
            Statement::DidRegistration(s) => {
                let statement = serde_json::to_value(statement)?;
                let id = s.get_id();
                let registered_by = s.get_registered_by();
                let type_ = s.get_type();
                let did = s.get_did();
                let statement_data = serde_json::to_string(&statement)?;
                log::debug!("Registering {type_} did '{id}'");
                sqlx::query(
                    r#"
                    INSERT OR IGNORE INTO did_statements
                    (id, statement, registered_by, type, did) VALUES (?1, ?2, ?3, ?4, ?5)
                "#,
                )
                .bind(&id)
                .bind(&statement_data)
                .bind(registered_by)
                .bind(type_)
                .bind(did)
                .execute(&self.pool)
                .await?;

                Ok(())
            }
            Statement::GovernanceRegistration(s) => {
                let statement = serde_json::to_value(statement)?;
                let id = s.get_id();
                let statement_data = serde_json::to_string(&statement)?;
                log::debug!("Registering governance '{id}'");
                sqlx::query(
                    r#"
                    INSERT OR IGNORE INTO governance_statements
                    (id, statement, registered_by, subject, document) VALUES (?1, ?2, ?3, ?4, ?5)
                "#,
                )
                .bind(&id)
                .bind(&statement_data)
                .bind(&s.registered_by)
                .bind(&s.subject)
                .bind(&s.document)
                .execute(&self.pool)
                .await?;

                Ok(())
            }
            Statement::ComputationRegistration(_)
            | Statement::AssociationRegistration(_)
            | Statement::DataRegistration(_)
            | Statement::MetadataRegistration(_)
            | Statement::StorageRegistration(_)
            | Statement::EntityRegistration(_) => {
                log::error!(
                    "Attempted to register a graph specific statement '{}' to the global store",
                    statement.get_type_string().unwrap_or("UNKNOWN".to_owned())
                );
                Ok(())
            }
        }
    }

    async fn get_global_statements(
        &self,
        statements: &mut HashMap<String, Statement>,
    ) -> Result<()> {
        // TODO: Get the Credential, CredDsse, CredSigStore, DID, Governance Statements
        // for ALL the previously fetched statements regardless of project
        let mut dids = HashSet::new();
        let mut credential_subjects = HashSet::new();

        for stmt in statements.values() {
            dids.insert(stmt.get_registered_by().to_owned());
            credential_subjects.insert(stmt.get_id().to_owned());
        }

        log::debug!("Getting credential statements for subjects: {credential_subjects:?}");
        let placeholders = vec!["?"; credential_subjects.len()].join(", ");
        let global_query = format!(
            r#"
            SELECT statement
            FROM credential_statements
            WHERE credential_subject IN ({})
        "#,
            placeholders
        );

        let mut sql_query = sqlx::query(&global_query);
        for credential_subject in &credential_subjects {
            sql_query = sql_query.bind(credential_subject);
        }

        let vc_rows = sql_query.fetch_all(&self.pool).await?;
        log::debug!("Found '{}' credential statements", vc_rows.len());

        let vc_statements = Self::parse_statement_rows(vc_rows)?;
        statements.extend(vc_statements);

        if !dids.is_empty() {
            log::debug!("Getting DID statements for subjects: {dids:?}");
            let placeholders = vec!["?"; dids.len()].join(", ");
            let global_query = format!(
                r#"
                SELECT
                  did.statement as statement
                  ,meta.statement as metadata
                  ,vc.statement as vc
                FROM did_statements did
                LEFT JOIN metadata_statements meta ON did.did = meta.subject
                LEFT JOIN credential_statements vc ON did.id = vc.credential_subject
                WHERE did IN ({})"#,
                placeholders
            );

            let mut sql_query = sqlx::query(&global_query);
            for did in &dids {
                sql_query = sql_query.bind(did);
            }

            let did_rows = sql_query.fetch_all(&self.pool).await?;
            log::debug!("Found '{}' did statements", did_rows.len());

            let did_statements = Self::parse_statement_rows(did_rows)?;
            statements.extend(did_statements);
        }

        Ok(())
    }
}

#[async_trait]
impl IStatementIdx for Sqlite {
    /// Creates a record in the "graphs" table
    async fn create_graph(
        &self,
        graph_id: &Uuid,
        name: &str,
        parent_id: Option<&Uuid>,
    ) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO graphs
            (graph_id, name, parent_id)
            VALUES (?1, ?2, ?3)
            "#,
        )
        .bind(graph_id.to_string())
        .bind(name)
        .bind(parent_id.map(|id| id.to_string()))
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn register_statement(
        &self,
        statement: &Statement,
        graph_id: Option<&Uuid>,
    ) -> Result<()> {
        log::trace!("Registering statement");
        match statement {
            Statement::ComputationRegistration(_)
            | Statement::AssociationRegistration(_)
            | Statement::DataRegistration(_)
            | Statement::MetadataRegistration(_)
            | Statement::StorageRegistration(_)
            | Statement::EntityRegistration(_) => {
                self.register_graph_statement(statement, graph_id).await
            }
            Statement::CredentialSigstoreBundleRegistration(_)
            | Statement::CredentialRegistration(_)
            | Statement::DidRegistration(_)
            | Statement::GovernanceRegistration(_)
            | Statement::CredentialDsseRegistration(_) => {
                self.register_global_statement(statement).await
            }
        }
    }

    /// Updates the link table to assign a statement to a graph
    async fn associate_statement_to_graph(
        &self,
        statement_id: &str,
        graph_id: &Uuid,
    ) -> Result<()> {
        sqlx::query(
            r#"
            INSERT OR IGNORE INTO statement_graph_link
            (statement_id, graph_id)
            VALUES (?1, ?2)
        "#,
        )
        .bind(statement_id)
        .bind(graph_id.to_string())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn retrieve_graph(&self, graph_id: &Uuid) -> Result<Graph> {
        log::info!("Retieving statements for graph {graph_id:?}");

        let mut graph: Graph = sqlx::query(
            r#"
            SELECT graph_id, name, parent_id
            FROM graphs g
            WHERE g.graph_id = ?1
        "#,
        )
        .bind(graph_id.to_string())
        .fetch_one(&self.pool)
        .await?
        .into();

        // Create placeholders for the IN clause
        let compute_query_str = r#"
            SELECT
              s.statement
              , vc.statement as vc
              , metadata.statement as metadata
              , did.statement as did
            FROM computation_statements s
            LEFT JOIN statement_graph_link l ON s.id = l.statement_id
            LEFT JOIN graphs g ON l.graph_id = g.graph_id
            LEFT JOIN credential_statements vc ON vc.credential_subject = s.id
            LEFT JOIN metadata_statements metadata on metadata.subject = s.id
            LEFT JOIN did_statements did ON s.registered_by = did.did
            WHERE g.graph_id = ?1
        "#;

        let compute_rows = sqlx::query(compute_query_str)
            .bind(graph_id.to_string())
            .fetch_all(&self.pool)
            .await?;

        if compute_rows.is_empty() {
            log::info!("No computation statements found for graph(s) {graph_id:?}");
            return Ok(graph);
        }

        let mut subjects: Vec<String> = Vec::new();

        log::debug!("Found '{}' compute statements", compute_rows.len());
        let mut statements = Self::parse_statement_rows(compute_rows)?;
        for statement in statements.values() {
            if let Statement::ComputationRegistration(s) = statement {
                subjects.extend(s.input.to_vec_string());
                subjects.extend(s.output.to_vec_string());
            }
        }

        // Get the Data & Metadata & Storage & Association & Entity statements
        // WHERE MD.subject/data/association IN compute.[inputs + outputs] AND in project or parent project
        log::debug!("Getting statements for subjects: {subjects:?}");
        // Build placeholders: (?2, ?3, ?4)
        let placeholders: Vec<String> = (2..=subjects.len() + 1)
            .map(|i| format!("?{}", i))
            .collect();
        let in_clause = format!("({})", placeholders.join(", "));

        // Gets all the statements registered under <graph_id> and it's parents
        let query = format!(
            r#"
            WITH RECURSIVE graph_hierarchy AS (
                SELECT graph_id, name, parent_id, 0 as level
                FROM graphs
                WHERE graph_id = ?1
                UNION ALL
                SELECT g.graph_id, g.name, g.parent_id, gh.level + 1
                FROM graphs g
                JOIN graph_hierarchy gh ON g.graph_id = gh.parent_id
            )
            SELECT DISTINCT
                COALESCE(data.statement, metadata.statement, storage.statement, association.statement) as statement,
                gh.graph_id,
                gh.level
            FROM graph_hierarchy gh
            LEFT JOIN statement_graph_link sgl ON gh.graph_id = sgl.graph_id
            LEFT JOIN data_statements data ON sgl.statement_id = data.id
            LEFT JOIN data_statement_subjects dss ON data.id = dss.statement_id
            LEFT JOIN metadata_statements metadata ON sgl.statement_id = metadata.id
            LEFT JOIN storage_statements storage ON sgl.statement_id = storage.id
            LEFT JOIN association_statements association ON sgl.statement_id = association.id
            LEFT JOIN entity_statements entity ON sgl.statement_id = entity.id
            LEFT JOIN entity_statement_subjects ess ON entity.id = ess.statement_id
            WHERE COALESCE(dss.subject, metadata.subject, storage.data, association.association, association.subject, ess.entity) IN {}
            ORDER BY gh.level;
            "#,
            in_clause
        );

        let mut sql_query = sqlx::query(&query).bind(graph_id.to_string());

        for subject in &subjects {
            sql_query = sql_query.bind(subject);
        }

        let rows = sql_query.fetch_all(&self.pool).await?;
        log::debug!("Found '{}' related statements", rows.len());
        statements.extend(Self::parse_statement_rows(rows)?);

        self.get_global_statements(&mut statements).await?;

        graph.statements = Some(statements.into_values().collect());
        Ok(graph)
    }

    async fn get_associations_for_subject(&self, subject: &str) -> Result<Vec<String>> {
        log::trace!("Retrieving associations for subject={subject}.");

        let rows: Vec<AssociationRow> = sqlx::query_as(
            r#"
            SELECT id, subject, association
            FROM association_statements
            WHERE subject = $1
            "#,
        )
        .bind(subject)
        .fetch_all(&self.pool)
        .await?;

        let mut associations = rows.into_iter().map(|r| r.association).collect::<Vec<_>>();

        associations.sort();
        associations.dedup();

        Ok(associations)
    }

    async fn get_subjects_for_association(&self, association: &str) -> Result<Vec<String>> {
        log::trace!("Retrieving subjects for association={association}.");

        let rows: Vec<AssociationRow> = sqlx::query_as(
            r#"
            SELECT id, subject, association
            FROM association_statements
            WHERE association = $1
            "#,
        )
        .bind(association)
        .fetch_all(&self.pool)
        .await?;

        let mut subjects = rows.into_iter().map(|r| r.subject).collect::<Vec<_>>();

        subjects.sort();
        subjects.dedup();

        Ok(subjects)
    }

    async fn get_graph_info(&self) -> Result<Vec<Graph>> {
        log::trace!("Retrieving all graph info");

        let rows: Vec<Graph> = sqlx::query_as(
            r#"
            SELECT graph_id, name, parent_id
            FROM graphs
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    async fn get_child_graph_info(&self, parent_id: &Uuid) -> Result<Vec<Graph>> {
        log::trace!("Retrieving child graph info for {parent_id:?}");

        let rows: Vec<Graph> = sqlx::query_as(
            r#"
            WITH RECURSIVE descendants AS (
                -- Base case: direct children
                SELECT graph_id, name, parent_id
                FROM graphs
                WHERE parent_id = ?1

                UNION ALL

                -- Recursive case: children of children
                SELECT g.graph_id, g.name, g.parent_id
                FROM graphs g
                INNER JOIN descendants d ON g.parent_id = d.graph_id
            )
            SELECT graph_id, name, parent_id
            FROM descendants
            "#,
        )
        .bind(parent_id.to_string())
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    async fn get_statement_by_id(&self, _id: &str) -> Result<Option<Statement>> {
        unimplemented!();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ssi::vc::Credential;

    use super::*;
    use crate::lineage::{
        graph_indexer::{sql_indexer::shared_tests, sql_lite::Sqlite},
        models::statements::{
            ComputationStatement, DataStatement, DidStatement, DidStatementRegular,
            MetadataStatement, StatementTrait, VcStatement,
        },
    };

    async fn db() -> Arc<Sqlite> {
        use std::sync::Once;
        static INIT: Once = Once::new();

        INIT.call_once(|| {
            let _ = env_logger::try_init();
        });

        // let db_file = PathBuf::from("graphs.db");
        // File::create(db_file).unwrap();
        // let db = Sqlite::new("graphs.db").await.unwrap();
        let db = Sqlite::new("sqlite::memory:").await.unwrap();
        db.init().await.unwrap();
        Arc::new(db)
    }

    #[tokio::test]
    /// Test registration of a computation statements
    async fn create_compute_record() {
        shared_tests::test_register_computation_statement(db().await).await;
    }

    #[tokio::test]
    /// Test registration of a data statements
    async fn create_data_record() {
        shared_tests::test_register_data_statement(db().await).await;
    }

    #[tokio::test]
    /// Test registration of a metadata statements
    async fn create_metadata_record() {
        shared_tests::test_register_metadata_statement(db().await).await;
    }

    #[tokio::test]
    /// Test registration of a storage statements
    async fn create_storage_record() {
        shared_tests::test_register_storage_statement(db().await).await;
    }

    #[tokio::test]
    /// Test registration of a association statements
    async fn create_association_record() {
        shared_tests::test_register_association_statement(db().await).await;
    }

    #[tokio::test]
    /// Test retrieval of associations by subject
    async fn get_association_by_subject() {
        shared_tests::test_association_get_by_subject(db().await).await;
    }

    #[tokio::test]
    /// Test retrieval of associations by association
    async fn get_association_by_association() {
        shared_tests::test_association_get_by_association(db().await).await;
    }

    #[tokio::test]
    /// Test registration of a entity statements
    async fn create_entity_record() {
        shared_tests::test_register_entity_statement(db().await).await;
    }

    #[tokio::test]
    /// Test registration of a sigstore statements
    async fn create_sigstore_record() {
        shared_tests::test_register_sigstore_statement(db().await).await;
    }

    #[tokio::test]
    /// Test registration of a credential statements
    async fn create_credential_record() {
        shared_tests::test_register_credential_statement(db().await).await;
    }

    #[tokio::test]
    /// Test registration of a dsse statements
    async fn create_dsse_record() {
        shared_tests::test_register_dsse_statement(db().await).await;
    }

    #[tokio::test]
    /// Test registration of a REGULAR did statements
    async fn create_regular_did_record() {
        shared_tests::test_register_regular_did_statement(db().await).await;
    }

    #[tokio::test]
    /// Test registration of a AmdSev did statements
    async fn create_amd_sev_did_record() {
        shared_tests::test_register_amd_sev_did_statement(db().await).await;
    }

    #[tokio::test]
    /// Test registration of a Azure VComp did statements
    async fn create_azure_vcomp_did_record() {
        shared_tests::test_register_azure_vcomp_did_statement(db().await).await;
    }

    #[tokio::test]
    /// Test registration of a Docker did statements
    async fn create_docker_did_record() {
        shared_tests::test_register_docker_did_statement(db().await).await;
    }

    #[tokio::test]
    /// Test registration of an Intel TDX Docker did statements
    async fn create_intel_tdx_did_record() {
        shared_tests::test_register_intel_tdx_did_statement(db().await).await;
    }

    #[tokio::test]
    /// Test registration of a governance statements
    async fn create_governance_record() {
        shared_tests::test_register_governance_statement(db().await).await;
    }

    #[tokio::test]
    /// Test that graph records get created
    async fn create_graph_record() {
        shared_tests::test_create_graph(db().await).await;
    }

    #[tokio::test]
    /// Test that graphs can be 'nested' under under graphs
    async fn create_graph_with_parent() {
        shared_tests::test_create_graph_with_parent(db().await).await;
    }

    #[tokio::test]
    /// Test that statements are retrieved from the heirarchy
    async fn statement_retrieval_with_heirarchy() {
        shared_tests::test_statement_retrieval_with_hierarchy(db().await).await;
    }

    #[tokio::test]
    /// Test that global statements are retrieved
    async fn global_statement_retrieval() {
        let mut statement_count = 0;
        // Create statements under nested projects, and make sure the query returns them all
        let db = db().await;

        // Create a graph id
        let graph_id = uuid::uuid!("00000000-0000-0000-0000-500000000011");
        db.create_graph(&graph_id, "Global Statements", None)
            .await
            .unwrap();

        // --> Create a DID Statement
        let did = String::from("did:key:global_did");
        let did_statement = DidStatementRegular::create(did.clone(), did.clone(), None)
            .await
            .unwrap();

        let did_statement = DidStatement::Regular(did_statement);

        let did_vc = create_vc_for_test(&did_statement.get_id()).await;
        // <-- Create a DID Statement

        // --> Create Data Statements under root graph
        let input_data = vec![
            "urn:cid:comp_data_input_1".to_owned(),
            "urn:cid:comp_data_input_2".to_owned(),
        ];
        let input_data_statement = DataStatement::create(input_data.clone(), did.clone(), None)
            .await
            .unwrap();

        let data_input_vc = create_vc_for_test(&input_data_statement.get_id()).await;

        let output_data = vec!["urn:cid:comp_data_output".to_owned()];
        let output_data_statement = DataStatement::create(output_data.clone(), did.clone(), None)
            .await
            .unwrap();

        let data_output_vc = create_vc_for_test(&output_data_statement.get_id()).await;
        // <-- Create Data Statements under root graph

        // --> Create a Metadata statement
        let input_metadata_statement = MetadataStatement::create(
            "urn:cid:comp_data_input_1".to_owned(),
            String::from("metadata"),
            did.clone(),
            None,
        )
        .await
        .unwrap();
        let input_metadata_statement_id = input_metadata_statement.get_id();
        // <-- Create a Metadata statement

        // --> Create Computation with the same data cids under the child graph
        let computation_statement = ComputationStatement::create(
            None,
            input_data,
            output_data,
            did.clone(),
            None,
            did.clone(),
            None,
        )
        .await
        .unwrap();

        let compute_vc = create_vc_for_test(&computation_statement.get_id()).await;
        db.register_statement(&compute_vc, None).await.unwrap();
        statement_count += 1;

        let comp_statement_id = computation_statement.get_id();
        db.register_statement(
            &Statement::ComputationRegistration(computation_statement),
            Some(&graph_id),
        )
        .await
        .unwrap();
        statement_count += 1;

        let comp_metadata_statement = MetadataStatement::create(
            comp_statement_id,
            String::from("metadata for the computation statement"),
            did,
            None,
        )
        .await
        .unwrap();
        let metadata_statement_id = comp_metadata_statement.get_id();

        db.register_statement(
            &Statement::MetadataRegistration(comp_metadata_statement),
            Some(&graph_id),
        )
        .await
        .unwrap();
        statement_count += 1;

        let vc = create_vc_for_test(&metadata_statement_id).await;
        db.register_statement(&vc, None).await.unwrap();
        statement_count += 1;
        // <-- Create Computation with the same data cids under the child graph

        // Check that the correct number of statements are retrieved
        let graph = db.retrieve_graph(&graph_id).await.unwrap();
        assert_eq!(graph.statements.as_ref().unwrap().len(), statement_count);

        db.register_statement(&did_vc, None).await.unwrap();
        statement_count += 1;
        db.register_statement(&Statement::DidRegistration(Box::new(did_statement)), None)
            .await
            .unwrap();
        statement_count += 1;

        let graph = db.retrieve_graph(&graph_id).await.unwrap();
        assert_eq!(graph.statements.as_ref().unwrap().len(), statement_count);

        db.register_statement(&data_input_vc, None).await.unwrap();
        statement_count += 1;
        db.register_statement(
            &Statement::DataRegistration(input_data_statement),
            Some(&graph_id),
        )
        .await
        .unwrap();
        statement_count += 1;
        let graph = db.retrieve_graph(&graph_id).await.unwrap();
        assert_eq!(graph.statements.as_ref().unwrap().len(), statement_count);

        db.register_statement(
            &Statement::DataRegistration(output_data_statement),
            Some(&graph_id),
        )
        .await
        .unwrap();
        statement_count += 1;
        let graph = db.retrieve_graph(&graph_id).await.unwrap();
        assert_eq!(graph.statements.as_ref().unwrap().len(), statement_count);

        let metadata_vc = create_vc_for_test(&input_metadata_statement_id).await;
        db.register_statement(&metadata_vc, None).await.unwrap();
        statement_count += 1;
        db.register_statement(
            &Statement::MetadataRegistration(input_metadata_statement),
            Some(&graph_id),
        )
        .await
        .unwrap();
        statement_count += 1;
        let graph = db.retrieve_graph(&graph_id).await.unwrap();
        assert_eq!(graph.statements.as_ref().unwrap().len(), statement_count);

        db.register_statement(&data_output_vc, None).await.unwrap();
        statement_count += 1;
        let graph = db.retrieve_graph(&graph_id).await.unwrap();
        assert_eq!(graph.statements.as_ref().unwrap().len(), statement_count);
    }

    async fn create_vc_for_test(subject: &str) -> Statement {
        let did = "did:key:vc_for_test";
        let doc_str = format!(
            r#"{{
                "@context": "https://www.w3.org/2018/credentials/v1",
                "id": "http://example.org/credentials/3731",
                "type": ["VerifiableCredential"],
                "issuer": "did:example:30e07a529f32d234f6181736bd3",
                "issuanceDate": "2020-08-19T21:41:50Z",
                "credentialSubject": {{
                    "id": "{}"
                }}
            }}"#,
            subject
        );
        let doc: Credential = serde_json::from_str(&doc_str).unwrap();
        let statement = VcStatement::create(doc, did.to_owned(), None)
            .await
            .unwrap();

        Statement::CredentialRegistration(statement)
    }
}
