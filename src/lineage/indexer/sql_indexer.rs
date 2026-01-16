use std::{collections::HashMap, sync::Arc};

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::lineage::models::statements::Statement;

#[async_trait]
pub trait IStatementIdx {
    /// Adds the statement to sql
    async fn register_statement(&self, statement: Statement, attributes: Value) -> Result<()>;
    /// Returns the statements from sql, and filtered by the provided filter query
    async fn retrieve_statements(
        &self,
        filter_query: Option<&str>,
    ) -> Result<(Vec<Statement>, HashMap<String, Value>)>;
    async fn get_unique_attributes(&self) -> Result<HashMap<String, Filter>>;
    async fn get_statement_by_id(&self, id: &str) -> Result<Option<Statement>>;
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Filter {
    /// (Future Use)-Number of distinct values.
    pub n: usize,
    pub values: Option<Vec<Value>>,
}

pub mod tests {
    use serde_json::json;

    use super::*;
    use crate::lineage::models::statements::{
        data_statement::DataStatement, entity_statement::EntityStatement,
    };

    pub async fn test_statement_filter_type_equals(db: Arc<dyn IStatementIdx + Send + Sync>) {
        let statement_1 = Statement::DataRegistration(
            DataStatement::create(
                vec!["urn:cid:data1".to_string()],
                "did:key:example1".to_string(),
                None,
            )
            .await
            .unwrap(),
        );
        let statement_2 = Statement::EntityRegistration(
            EntityStatement::create(
                vec!["urn:uuid:123".to_string()],
                "did:key:example1".to_string(),
                None,
            )
            .await
            .unwrap(),
        );

        db.register_statement(statement_1.clone(), json!({}))
            .await
            .unwrap();
        db.register_statement(statement_2.clone(), json!({}))
            .await
            .unwrap();

        let (statements_data, _) = db
            .retrieve_statements(Some("statementType == 'DataRegistration'"))
            .await
            .unwrap();

        match &statements_data[..] {
            [single] => assert_eq!(single, &statement_1),
            _ => panic!(
                "Expected exactly one DataRegistration statement, got {:?}",
                statements_data
            ),
        }

        let (statements_entity, _) = db
            .retrieve_statements(Some("statementType == 'EntityRegistration'"))
            .await
            .unwrap();

        match &statements_entity[..] {
            [single] => assert_eq!(single, &statement_2),
            _ => panic!(
                "Expected exactly one EntityRegistration statement, got {:?}",
                statements_entity
            ),
        }

        let (statements_computation, _) = db
            .retrieve_statements(Some("statementType == 'ComputationRegistration'"))
            .await
            .unwrap();

        assert!(
            statements_computation.is_empty(),
            "Expected no ComputationRegistration statements, got {:?}",
            statements_computation
        );
    }

    pub async fn test_statement_filter_attribute_equals(db: Arc<dyn IStatementIdx + Send + Sync>) {
        let statement_1 = Statement::DataRegistration(
            DataStatement::create(
                vec!["urn:cid:data1".to_string()],
                "did:key:example1".to_string(),
                None,
            )
            .await
            .unwrap(),
        );
        let attributes_1 = serde_json::json!({
            "project": "alpha",
            "session": "001",
        });

        let statement_2 = Statement::DataRegistration(
            DataStatement::create(
                vec!["urn:cid:data2".to_string()],
                "did:key:example1".to_string(),
                None,
            )
            .await
            .unwrap(),
        );
        let attributes_2 = serde_json::json!({
            "project": "alpha",
            "session": "002",
        });

        db.register_statement(statement_1.clone(), attributes_1)
            .await
            .unwrap();
        db.register_statement(statement_2.clone(), attributes_2)
            .await
            .unwrap();

        let (statements_project_alpha, _) = db
            .retrieve_statements(Some("attributes.project == 'alpha'"))
            .await
            .unwrap();

        assert!(
            statements_project_alpha.len() == 2,
            "Expected 2 statements for project alpha, got {:?}",
            statements_project_alpha
        );
        assert!(statements_project_alpha.contains(&statement_1));
        assert!(statements_project_alpha.contains(&statement_2));

        let (statements_session_001, _) = db
            .retrieve_statements(Some("attributes.session == '001'"))
            .await
            .unwrap();

        assert!(
            statements_session_001.len() == 1,
            "Expected 1 statement for session 001, got {:?}",
            statements_session_001
        );
        assert!(statements_session_001.contains(&statement_1));
    }

    pub async fn test_statement_filter_attribute_less_than(
        db: Arc<dyn IStatementIdx + Send + Sync>,
    ) {
        let statement_1 = Statement::DataRegistration(
            DataStatement::create(
                vec!["urn:cid:data1".to_string()],
                "did:key:example1".to_string(),
                None,
            )
            .await
            .unwrap(),
        );
        let attributes_1 = serde_json::json!({
            "size": 400,
        });

        let statement_2 = Statement::DataRegistration(
            DataStatement::create(
                vec!["urn:cid:data2".to_string()],
                "did:key:example1".to_string(),
                None,
            )
            .await
            .unwrap(),
        );
        let attributes_2 = serde_json::json!({
            "size": 500,
        });

        db.register_statement(statement_1.clone(), attributes_1)
            .await
            .unwrap();
        db.register_statement(statement_2.clone(), attributes_2)
            .await
            .unwrap();

        let (statements_size_lt_350, _) = db
            .retrieve_statements(Some("attributes.size < 350"))
            .await
            .unwrap();

        assert!(
            statements_size_lt_350.is_empty(),
            "Expected no statements for size < 350 got {:?}",
            statements_size_lt_350
        );

        let (statements_size_lt_450, _) = db
            .retrieve_statements(Some("attributes.size < 450"))
            .await
            .unwrap();

        match &statements_size_lt_450[..] {
            [single] => assert_eq!(single, &statement_1),
            _ => panic!(
                "Expected exactly one statement for size < 450, got {:?}",
                statements_size_lt_450
            ),
        }

        let (statements_size_lt_550, _) = db
            .retrieve_statements(Some("attributes.size < 550"))
            .await
            .unwrap();

        assert!(
            statements_size_lt_550.len() == 2,
            "Expected 2 statements for size < 550, got {:?}",
            statements_size_lt_550
        );
        assert!(statements_size_lt_550.contains(&statement_1));
        assert!(statements_size_lt_550.contains(&statement_2));
    }

    pub async fn test_statement_filter_attribute_greater_than(
        db: Arc<dyn IStatementIdx + Send + Sync>,
    ) {
        let statement_1 = Statement::DataRegistration(
            DataStatement::create(
                vec!["urn:cid:data1".to_string()],
                "did:key:example1".to_string(),
                None,
            )
            .await
            .unwrap(),
        );
        let attributes_1 = serde_json::json!({
            "size": 400,
        });

        let statement_2 = Statement::DataRegistration(
            DataStatement::create(
                vec!["urn:cid:data2".to_string()],
                "did:key:example1".to_string(),
                None,
            )
            .await
            .unwrap(),
        );
        let attributes_2 = serde_json::json!({
            "size": 500,
        });

        db.register_statement(statement_1.clone(), attributes_1)
            .await
            .unwrap();
        db.register_statement(statement_2.clone(), attributes_2)
            .await
            .unwrap();

        let (statements_size_gt_350, _) = db
            .retrieve_statements(Some("attributes.size > 350"))
            .await
            .unwrap();

        assert!(
            statements_size_gt_350.len() == 2,
            "Expected 2 statements for size > 350, got {:?}",
            statements_size_gt_350
        );
        assert!(statements_size_gt_350.contains(&statement_1));
        assert!(statements_size_gt_350.contains(&statement_2));

        let (statements_size_gt_450, _) = db
            .retrieve_statements(Some("attributes.size > 450"))
            .await
            .unwrap();

        match &statements_size_gt_450[..] {
            [single] => assert_eq!(single, &statement_2),
            _ => panic!(
                "Expected exactly one statement for size > 450, got {:?}",
                statements_size_gt_450
            ),
        }

        let (statements_size_gt_550, _) = db
            .retrieve_statements(Some("attributes.size > 550"))
            .await
            .unwrap();

        assert!(
            statements_size_gt_550.is_empty(),
            "Expected no statements for size > 550, got {:?}",
            statements_size_gt_550
        );
    }

    pub async fn test_statement_filter_and(db: Arc<dyn IStatementIdx + Send + Sync>) {
        let statement_1 = Statement::DataRegistration(
            DataStatement::create(
                vec!["urn:cid:data1".to_string()],
                "did:key:example1".to_string(),
                None,
            )
            .await
            .unwrap(),
        );
        let attributes_1 = serde_json::json!({
            "project": "alpha",
            "session": "001",
        });

        let statement_2 = Statement::DataRegistration(
            DataStatement::create(
                vec!["urn:cid:data2".to_string()],
                "did:key:example1".to_string(),
                None,
            )
            .await
            .unwrap(),
        );
        let attributes_2 = serde_json::json!({
            "project": "alpha",
            "session": "002",
        });

        let statement_3 = Statement::DataRegistration(
            DataStatement::create(
                vec!["urn:cid:data3".to_string()],
                "did:key:example1".to_string(),
                None,
            )
            .await
            .unwrap(),
        );
        let attributes_3 = serde_json::json!({
            "project": "beta",
            "session": "001",
        });

        db.register_statement(statement_1.clone(), attributes_1)
            .await
            .unwrap();
        db.register_statement(statement_2.clone(), attributes_2)
            .await
            .unwrap();
        db.register_statement(statement_3.clone(), attributes_3)
            .await
            .unwrap();

        let (statements_project_alpha_and_session_001, _) = db
            .retrieve_statements(Some(
                "attributes.project == 'alpha' && attributes.session == '001'",
            ))
            .await
            .unwrap();

        assert!(
            statements_project_alpha_and_session_001.len() == 1,
            "Expected 1 statement for project alpha and session 001, got {:?}",
            statements_project_alpha_and_session_001
        );
        assert!(statements_project_alpha_and_session_001.contains(&statement_1));
    }

    pub async fn test_statement_filter_or(db: Arc<dyn IStatementIdx + Send + Sync>) {
        let statement_1 = Statement::DataRegistration(
            DataStatement::create(
                vec!["urn:cid:data1".to_string()],
                "did:key:example1".to_string(),
                None,
            )
            .await
            .unwrap(),
        );
        let attributes_1 = serde_json::json!({
            "project": "alpha",
            "session": "001",
        });

        let statement_2 = Statement::DataRegistration(
            DataStatement::create(
                vec!["urn:cid:data2".to_string()],
                "did:key:example1".to_string(),
                None,
            )
            .await
            .unwrap(),
        );
        let attributes_2 = serde_json::json!({
            "project": "alpha",
            "session": "002",
        });

        let statement_3 = Statement::DataRegistration(
            DataStatement::create(
                vec!["urn:cid:data3".to_string()],
                "did:key:example1".to_string(),
                None,
            )
            .await
            .unwrap(),
        );
        let attributes_3 = serde_json::json!({
            "project": "beta",
            "session": "001",
        });

        db.register_statement(statement_1.clone(), attributes_1)
            .await
            .unwrap();
        db.register_statement(statement_2.clone(), attributes_2)
            .await
            .unwrap();
        db.register_statement(statement_3.clone(), attributes_3)
            .await
            .unwrap();

        let (statements_project_alpha_or_session_001, _) = db
            .retrieve_statements(Some(
                "attributes.project == 'alpha' || attributes.session == '001'",
            ))
            .await
            .unwrap();

        assert!(
            statements_project_alpha_or_session_001.len() == 3,
            "Expected 3 statements for project alpha or session 001, got {:?}",
            statements_project_alpha_or_session_001
        );
        assert!(statements_project_alpha_or_session_001.contains(&statement_1));
        assert!(statements_project_alpha_or_session_001.contains(&statement_2));
        assert!(statements_project_alpha_or_session_001.contains(&statement_3));

        let (statements_project_alpha_or_session_002, _) = db
            .retrieve_statements(Some(
                "attributes.project == 'alpha' || attributes.session == '002'",
            ))
            .await
            .unwrap();

        assert!(
            statements_project_alpha_or_session_002.len() == 2,
            "Expected 2 statements for project alpha or session 002, got {:?}",
            statements_project_alpha_or_session_002
        );
        assert!(statements_project_alpha_or_session_002.contains(&statement_1));
        assert!(statements_project_alpha_or_session_002.contains(&statement_2));

        let (statements_project_beta_or_session_001, _) = db
            .retrieve_statements(Some(
                "attributes.project == 'beta' || attributes.session == '001'",
            ))
            .await
            .unwrap();

        assert!(
            statements_project_beta_or_session_001.len() == 2,
            "Expected 2 statements for project beta or session 001, got {:?}",
            statements_project_beta_or_session_001
        );
        assert!(statements_project_beta_or_session_001.contains(&statement_1));
        assert!(statements_project_beta_or_session_001.contains(&statement_3));

        let (statements_project_beta_or_session_002, _) = db
            .retrieve_statements(Some(
                "attributes.project == 'beta' || attributes.session == '002'",
            ))
            .await
            .unwrap();

        assert!(
            statements_project_beta_or_session_002.len() == 2,
            "Expected 2 statements for project beta or session 002, got {:?}",
            statements_project_beta_or_session_002
        );
        assert!(statements_project_beta_or_session_002.contains(&statement_2));
        assert!(statements_project_beta_or_session_002.contains(&statement_3));

        let (statements_project_gamma_or_session_003, _) = db
            .retrieve_statements(Some(
                "attributes.project == 'gamma' || attributes.session == '003'",
            ))
            .await
            .unwrap();

        assert!(
            statements_project_gamma_or_session_003.is_empty(),
            "Expected no statements for project gamma or session 003, got {:?}",
            statements_project_gamma_or_session_003
        );
    }

    pub async fn test_statement_filter_not(db: Arc<dyn IStatementIdx + Send + Sync>) {
        let statement_1 = Statement::DataRegistration(
            DataStatement::create(
                vec!["urn:cid:data1".to_string()],
                "did:key:example1".to_string(),
                None,
            )
            .await
            .unwrap(),
        );
        let attributes_1 = serde_json::json!({
            "project": "alpha",
            "session": "001",
        });

        let statement_2 = Statement::DataRegistration(
            DataStatement::create(
                vec!["urn:cid:data2".to_string()],
                "did:key:example1".to_string(),
                None,
            )
            .await
            .unwrap(),
        );
        let attributes_2 = serde_json::json!({
            "project": "alpha",
            "session": "002",
        });

        db.register_statement(statement_1.clone(), attributes_1)
            .await
            .unwrap();
        db.register_statement(statement_2.clone(), attributes_2)
            .await
            .unwrap();

        let (statements_not_project_alpha, _) = db
            .retrieve_statements(Some("attributes.project != 'alpha'"))
            .await
            .unwrap();

        assert!(
            statements_not_project_alpha.is_empty(),
            "Expected no statements not in project alpha, got {:?}",
            statements_not_project_alpha
        );

        let (statements_not_session_001, _) = db
            .retrieve_statements(Some("attributes.session != '001'"))
            .await
            .unwrap();

        match &statements_not_session_001[..] {
            [single] => assert_eq!(single, &statement_2),
            _ => panic!(
                "Expected exactly one statement not in session 001, got {:?}",
                statements_not_session_001
            ),
        }

        let (statements_not_session_002, _) = db
            .retrieve_statements(Some("attributes.session != '002'"))
            .await
            .unwrap();

        match &statements_not_session_002[..] {
            [single] => assert_eq!(single, &statement_1),
            _ => panic!(
                "Expected exactly one statement not in session 002, got {:?}",
                statements_not_session_002
            ),
        }
    }

    pub async fn test_statement_filter_dont_treat_strings_as_numbers(
        db: Arc<dyn IStatementIdx + Send + Sync>,
    ) {
        let statement_1 = Statement::DataRegistration(
            DataStatement::create(
                vec!["urn:cid:data1".to_string()],
                "did:key:example1".to_string(),
                None,
            )
            .await
            .unwrap(),
        );
        let attributes_1 = serde_json::json!({
            "size": "400",
        });

        let statement_2 = Statement::DataRegistration(
            DataStatement::create(
                vec!["urn:cid:data2".to_string()],
                "did:key:example1".to_string(),
                None,
            )
            .await
            .unwrap(),
        );
        let attributes_2 = serde_json::json!({
            "size": "500",
        });

        db.register_statement(statement_1.clone(), attributes_1)
            .await
            .unwrap();
        db.register_statement(statement_2.clone(), attributes_2)
            .await
            .unwrap();

        let (statements_size_eq_400_num, _) = db
            .retrieve_statements(Some("attributes.size == 400"))
            .await
            .unwrap();

        assert!(
            statements_size_eq_400_num.is_empty(),
            "Expected no statements for size = 400 (number) got {:?}",
            statements_size_eq_400_num
        );

        let (statements_size_eq_400_str, _) = db
            .retrieve_statements(Some("attributes.size == '400'"))
            .await
            .unwrap();

        match &statements_size_eq_400_str[..] {
            [single] => assert_eq!(single, &statement_1),
            _ => panic!(
                "Expected exactly one statement for size = 400 (string), got {:?}",
                statements_size_eq_400_str
            ),
        }

        let (statements_size_lt_450, _) = db
            .retrieve_statements(Some("attributes.size < 450"))
            .await
            .unwrap();

        assert!(
            statements_size_lt_450.is_empty(),
            "Expected no statements for size < 450 got {:?}",
            statements_size_lt_450
        );

        let (statements_size_gt_450, _) = db
            .retrieve_statements(Some("attributes.size > 450"))
            .await
            .unwrap();

        assert!(
            statements_size_gt_450.is_empty(),
            "Expected no statements for size > 450 got {:?}",
            statements_size_gt_450
        );
    }

    pub async fn test_statement_filter_dont_treat_numbers_as_strings(
        db: Arc<dyn IStatementIdx + Send + Sync>,
    ) {
        let statement_1 = Statement::DataRegistration(
            DataStatement::create(
                vec!["urn:cid:data1".to_string()],
                "did:key:example1".to_string(),
                None,
            )
            .await
            .unwrap(),
        );
        let attributes_1 = serde_json::json!({
            "size": 400,
        });

        let statement_2 = Statement::DataRegistration(
            DataStatement::create(
                vec!["urn:cid:data2".to_string()],
                "did:key:example1".to_string(),
                None,
            )
            .await
            .unwrap(),
        );
        let attributes_2 = serde_json::json!({
            "size": 500,
        });

        db.register_statement(statement_1.clone(), attributes_1)
            .await
            .unwrap();
        db.register_statement(statement_2.clone(), attributes_2)
            .await
            .unwrap();

        let (statements_size_eq_400_str, _) = db
            .retrieve_statements(Some("attributes.size == '400'"))
            .await
            .unwrap();

        assert!(
            statements_size_eq_400_str.is_empty(),
            "Expected no statements for size = 400 (string) got {:?}",
            statements_size_eq_400_str
        );

        let (statements_size_eq_400_num, _) = db
            .retrieve_statements(Some("attributes.size == 400"))
            .await
            .unwrap();

        match &statements_size_eq_400_num[..] {
            [single] => assert_eq!(single, &statement_1),
            _ => panic!(
                "Expected exactly one statement for size = 400 (number), got {:?}",
                statements_size_eq_400_num
            ),
        }

        let (statements_size_lt_450, _) = db
            .retrieve_statements(Some("attributes.size < 450"))
            .await
            .unwrap();

        match &statements_size_lt_450[..] {
            [single] => assert_eq!(single, &statement_1),
            _ => panic!(
                "Expected exactly one statement for size < 450, got {:?}",
                statements_size_lt_450
            ),
        }

        let (statements_size_gt_450, _) = db
            .retrieve_statements(Some("attributes.size > 450"))
            .await
            .unwrap();

        match &statements_size_gt_450[..] {
            [single] => assert_eq!(single, &statement_2),
            _ => panic!(
                "Expected exactly one statement for size > 450, got {:?}",
                statements_size_gt_450
            ),
        }
    }
}
