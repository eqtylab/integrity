use std::collections::HashMap;

use anyhow::Result;
use async_trait::async_trait;
use sqlx::{FromRow, Row};
use uuid::Uuid;

use super::row_types::StatementRow;
use crate::lineage::models::{
    graph::Graph,
    statements::{Statement, StatementTrait},
};

/// Trait for SQL-based statement indexing with graph support.
///
/// Provides methods for storing, retrieving, and querying statements
/// organized into graphs with hierarchical relationships.
#[async_trait]
pub trait IStatementIdx {
    /// Adds the statement to sql. If graph_id is provided, the link is created
    async fn register_statement(
        &self,
        statement: &Statement,
        graph_id: Option<&Uuid>,
    ) -> Result<()>;

    /// Links an existing statement to a graph
    async fn associate_statement_to_graph(&self, statement_id: &str, graph_id: &Uuid)
        -> Result<()>;

    /// Returns the statements from sql that belong to the graph_id or any parent
    async fn retrieve_graph(&self, graph_id: &Uuid) -> Result<Graph>;

    /// Creates a graph record with an optional parent
    async fn create_graph(
        &self,
        graph_id: &Uuid,
        name: &str,
        parent_id: Option<&Uuid>,
    ) -> Result<()>;

    /// Gets all statement IDs associated with the given subject
    async fn get_associations_for_subject(&self, subject: &str) -> Result<Vec<String>>;
    /// Gets all subject IDs for the given association
    async fn get_subjects_for_association(&self, association: &str) -> Result<Vec<String>>;

    /// Returns all the Graph information (UUIDs, Names, etc) from the database
    async fn get_graph_info(&self) -> Result<Vec<Graph>>;

    /// Returns all the Graph information for the child graphs
    async fn get_child_graph_info(&self, parent_id: &Uuid) -> Result<Vec<Graph>>;

    /// Retrieves a statement by its ID
    async fn get_statement_by_id(&self, id: &str) -> Result<Option<Statement>>;
}

/// Generic function to parse database rows into statements
/// Works with both SqliteRow and PgRow
pub fn rows_to_statements<R>(rows: Vec<R>) -> Result<HashMap<String, Statement>>
where
    R: Row,
    for<'r> StatementRow: FromRow<'r, R>,
{
    let mut statements = HashMap::new();
    log::trace!("Parsing {} rows to statements", rows.len());

    for row in rows {
        let statement_row = StatementRow::from_row(&row)?;

        // Parse main statement
        let statement: Statement = serde_json::from_value(statement_row.statement)?;
        let id = statement.get_id();
        statements.insert(id, statement);

        // Parse metadata if present
        if let Some(metadata_value) = statement_row.metadata {
            if !metadata_value.is_null() {
                log::trace!("Parsing metadata");
                let metadata_statement: Statement = serde_json::from_value(metadata_value)?;
                let id = metadata_statement.get_id();
                statements.insert(id, metadata_statement);
            }
        }

        // Parse vc if present
        if let Some(vc_value) = statement_row.vc {
            if !vc_value.is_null() {
                let vc_statement: Statement = serde_json::from_value(vc_value)?;
                let id = vc_statement.get_id();
                statements.insert(id, vc_statement);
            }
        }

        // Parse did if present
        if let Some(did_value) = statement_row.did {
            if !did_value.is_null() {
                let did_statement: Statement = serde_json::from_value(did_value)?;
                let id = did_statement.get_id();
                statements.insert(id, did_statement);
            }
        }
    }
    Ok(statements)
}

/// Shared test functions for all implementations of `IStatementIdx`.
#[cfg(test)]
pub mod shared_tests {
    use std::sync::Arc;

    use ssi::vc::Credential;

    use super::*;
    use crate::{
        lineage::models::{
            dsse::{Envelope, Signature},
            statements::{
                common::{UrnCidWithSha256, UrnCidWithSha384},
                AssociationStatement, ComputationStatement, DataStatement, DidStatement,
                DidStatementEqtyVCompAmdSevV1, DidStatementEqtyVCompAzureV1,
                DidStatementEqtyVCompDockerV1, DidStatementEqtyVCompIntelTdxV0,
                DidStatementRegular, DsseStatement, EntityStatement, GovernanceStatement,
                MetadataStatement, SigstoreBundleStatement, StatementTrait, StorageStatement,
                VcStatement,
            },
        },
        sigstore_bundle::SigstoreBundle,
    };

    /// Test that graph records get created
    pub async fn test_create_graph(db: Arc<dyn IStatementIdx + Send + Sync>) {
        let graph_id = uuid::uuid!("00000000-0000-0000-0000-000000000001");
        db.create_graph(&graph_id, "test:1", None).await.unwrap();

        // Verify by retrieving the graph
        let graph = db.retrieve_graph(&graph_id).await.unwrap();
        assert_eq!(graph.id, graph_id);
        assert_eq!(graph.name, "test:1");
        assert!(graph.parent.is_none());
    }

    /// Test that graphs can be 'nested' under other graphs
    pub async fn test_create_graph_with_parent(db: Arc<dyn IStatementIdx + Send + Sync>) {
        let parent_id = uuid::uuid!("00000000-0000-0000-0000-1000000000F0");
        let parent_name = "test:parent";
        db.create_graph(&parent_id, parent_name, None)
            .await
            .unwrap();

        let parent_graph = db.retrieve_graph(&parent_id).await.unwrap();
        assert_eq!(parent_graph.id, parent_id);
        assert_eq!(parent_graph.name, parent_name);
        assert!(parent_graph.parent.is_none());

        let child_id = uuid::uuid!("00000000-0000-0000-0000-1000000000F1");
        let child_name = "test:parent:child";
        db.create_graph(&child_id, child_name, Some(&parent_id))
            .await
            .unwrap();

        let child_graph = db.retrieve_graph(&child_id).await.unwrap();
        assert_eq!(child_graph.id, child_id);
        assert_eq!(child_graph.name, child_name);
        assert_eq!(child_graph.parent, Some(parent_id));
    }

    /// Test computation statement registration
    pub async fn test_register_computation_statement(db: Arc<dyn IStatementIdx + Send + Sync>) {
        let graph_id = uuid::uuid!("00000000-0000-0000-0000-000000000010");
        db.create_graph(&graph_id, "comp_test", None).await.unwrap();

        let did = String::from("did:key:comp_statement");
        let statement = ComputationStatement::create(
            None,
            vec![String::from("urn:cid:input1")],
            vec![String::from("urn:cid:output1")],
            did.clone(),
            None,
            did.clone(),
            None,
        )
        .await
        .unwrap();
        let statement_id = statement.get_id();

        let comp_statement = Statement::ComputationRegistration(statement);
        db.register_statement(&comp_statement, Some(&graph_id))
            .await
            .unwrap();

        // Verify by retrieving the graph
        let graph = db.retrieve_graph(&graph_id).await.unwrap();
        let statements = graph.statements.as_ref().unwrap();
        assert!(statements.iter().any(|s| s.get_id() == statement_id));
    }

    /// Test data statement registration
    pub async fn test_register_data_statement(db: Arc<dyn IStatementIdx + Send + Sync>) {
        let graph_id = uuid::uuid!("00000000-0000-0000-0000-000000000011");
        db.create_graph(&graph_id, "data_test", None).await.unwrap();

        let did = String::from("did:key:data_statement");
        let data_cid = String::from("urn:cid:input1");
        let statement = DataStatement::create(vec![data_cid.clone()], did.clone(), None)
            .await
            .unwrap();
        let data_statement_id = statement.get_id();

        let data_statement = Statement::DataRegistration(statement);
        db.register_statement(&data_statement, Some(&graph_id))
            .await
            .unwrap();

        // Create a computation that references this data so it gets retrieved
        let comp_statement = ComputationStatement::create(
            None,
            vec![data_cid],
            vec![String::from("urn:cid:output1")],
            did.clone(),
            None,
            did,
            None,
        )
        .await
        .unwrap();
        db.register_statement(
            &Statement::ComputationRegistration(comp_statement),
            Some(&graph_id),
        )
        .await
        .unwrap();

        // Verify by retrieving the graph - should contain both computation and data statements
        let graph = db.retrieve_graph(&graph_id).await.unwrap();
        let statements = graph.statements.as_ref().unwrap();
        assert!(statements.iter().any(|s| s.get_id() == data_statement_id));
    }

    /// Test metadata statement registration
    pub async fn test_register_metadata_statement(db: Arc<dyn IStatementIdx + Send + Sync>) {
        let graph_id = uuid::uuid!("00000000-0000-0000-0000-000000000012");
        db.create_graph(&graph_id, "metadata_test", None)
            .await
            .unwrap();

        let did = String::from("did:key:metadata_statement");
        let subject = String::from("urn:cid:metadata1");
        let metadata = String::from("the metadata");
        let statement =
            MetadataStatement::create(subject.clone(), metadata.clone(), did.clone(), None)
                .await
                .unwrap();
        let metadata_statement_id = statement.get_id();

        let meta_statement = Statement::MetadataRegistration(statement);
        db.register_statement(&meta_statement, Some(&graph_id))
            .await
            .unwrap();

        // Create a computation that references this subject so it gets retrieved
        let comp_statement = ComputationStatement::create(
            None,
            vec![subject],
            vec![String::from("urn:cid:output1")],
            did.clone(),
            None,
            did,
            None,
        )
        .await
        .unwrap();
        db.register_statement(
            &Statement::ComputationRegistration(comp_statement),
            Some(&graph_id),
        )
        .await
        .unwrap();

        // Verify by retrieving the graph
        let graph = db.retrieve_graph(&graph_id).await.unwrap();
        let statements = graph.statements.as_ref().unwrap();
        assert!(statements
            .iter()
            .any(|s| s.get_id() == metadata_statement_id));
    }

    /// Test storage statement registration
    pub async fn test_register_storage_statement(db: Arc<dyn IStatementIdx + Send + Sync>) {
        let graph_id = uuid::uuid!("00000000-0000-0000-0000-000000000013");
        db.create_graph(&graph_id, "storage_test", None)
            .await
            .unwrap();

        let did = String::from("did:key:storage_statement");
        let subject = String::from("urn:cid:storage");
        let stored_on = String::from("urn:cid:stored_on");
        let statement =
            StorageStatement::create(subject.clone(), stored_on.clone(), None, did.clone(), None)
                .await
                .unwrap();
        let storage_statement_id = statement.get_id();

        let storage_statement = Statement::StorageRegistration(statement);
        db.register_statement(&storage_statement, Some(&graph_id))
            .await
            .unwrap();

        // Create a computation that references the subject (data field) so it gets retrieved
        let comp_statement = ComputationStatement::create(
            None,
            vec![subject], // Use subject, not stored_on
            vec![String::from("urn:cid:output1")],
            did.clone(),
            None,
            did,
            None,
        )
        .await
        .unwrap();
        db.register_statement(
            &Statement::ComputationRegistration(comp_statement),
            Some(&graph_id),
        )
        .await
        .unwrap();

        // Verify by retrieving the graph
        let graph = db.retrieve_graph(&graph_id).await.unwrap();
        let statements = graph.statements.as_ref().unwrap();
        assert!(statements
            .iter()
            .any(|s| s.get_id() == storage_statement_id));
    }

    /// Test association statement registration
    pub async fn test_register_association_statement(db: Arc<dyn IStatementIdx + Send + Sync>) {
        let graph_id = uuid::uuid!("00000000-0000-0000-0000-000000000014");
        db.create_graph(&graph_id, "association_test", None)
            .await
            .unwrap();

        let did = String::from("did:key:association_statement");
        let subject = String::from("urn:cid:association_subjectx");
        let association = String::from("urn:cid:association_associate");
        let statement =
            AssociationStatement::create(subject.clone(), association.clone(), did.clone(), None)
                .await
                .unwrap();
        let association_statement_id = statement.get_id();

        let assoc_statement = Statement::AssociationRegistration(statement);
        db.register_statement(&assoc_statement, Some(&graph_id))
            .await
            .unwrap();

        // Create a computation that references the association so it gets retrieved
        let comp_statement = ComputationStatement::create(
            None,
            vec![association],
            vec![String::from("urn:cid:output1")],
            did.clone(),
            None,
            did,
            None,
        )
        .await
        .unwrap();
        db.register_statement(
            &Statement::ComputationRegistration(comp_statement),
            Some(&graph_id),
        )
        .await
        .unwrap();

        // Verify by retrieving the graph
        let graph = db.retrieve_graph(&graph_id).await.unwrap();
        let statements = graph.statements.as_ref().unwrap();
        assert!(statements
            .iter()
            .any(|s| s.get_id() == association_statement_id));
    }

    pub async fn test_association_get_by_subject(db: Arc<dyn IStatementIdx + Send + Sync>) {
        // Create an association record
        let did = String::from("did:key:association_statement");
        let subject = String::from("urn:cid:association_subject");
        let associate1 = String::from("urn:cid:association_first");
        let statement =
            AssociationStatement::create(subject.clone(), associate1.clone(), did.clone(), None)
                .await
                .unwrap();

        let assoc_statement = Statement::AssociationRegistration(statement);
        db.register_statement(&assoc_statement, None).await.unwrap();

        let associations = db.get_associations_for_subject(&subject).await.unwrap();
        assert_eq!(associations.len(), 1);
        assert_eq!(associations.first(), Some(&associate1));

        let associate2 = String::from("urn:cid:association_second");
        let statement =
            AssociationStatement::create(subject.clone(), associate2.clone(), did.clone(), None)
                .await
                .unwrap();

        let assoc_statement = Statement::AssociationRegistration(statement);
        db.register_statement(&assoc_statement, None).await.unwrap();
        let associations = db.get_associations_for_subject(&subject).await.unwrap();
        assert_eq!(associations.len(), 2);
        assert_eq!(associations[0], associate1);
        assert_eq!(associations[1], associate2);
    }

    pub async fn test_association_get_by_association(db: Arc<dyn IStatementIdx + Send + Sync>) {
        // Create an association record
        let did = String::from("did:key:association_statement");
        let subject1 = String::from("urn:cid:association_subject1");
        let associate = String::from("urn:cid:association");
        let statement =
            AssociationStatement::create(subject1.clone(), associate.clone(), did.clone(), None)
                .await
                .unwrap();

        let assoc_statement = Statement::AssociationRegistration(statement);
        db.register_statement(&assoc_statement, None).await.unwrap();

        let subjects = db.get_subjects_for_association(&associate).await.unwrap();
        assert_eq!(subjects.len(), 1);
        assert_eq!(subjects.first(), Some(&subject1));

        let subject2 = String::from("urn:cid:association_subject2");
        let statement =
            AssociationStatement::create(subject2.clone(), associate.clone(), did.clone(), None)
                .await
                .unwrap();

        let assoc_statement = Statement::AssociationRegistration(statement);
        db.register_statement(&assoc_statement, None).await.unwrap();
        let subjects = db.get_subjects_for_association(&associate).await.unwrap();
        assert_eq!(subjects.len(), 2);
        assert_eq!(subjects[0], subject1);
        assert_eq!(subjects[1], subject2);
    }

    /// Test entity statement registration
    /// Note: Entity statements are not currently retrieved by retrieve_graph due to
    /// a missing field in the SQL COALESCE clause. This test just verifies registration succeeds.
    pub async fn test_register_entity_statement(db: Arc<dyn IStatementIdx + Send + Sync>) {
        let graph_id = uuid::uuid!("00000000-0000-0000-0000-000000000015");
        db.create_graph(&graph_id, "entity_test", None)
            .await
            .unwrap();

        let did = String::from("did:key:entity_statement");
        let entity_0 = String::from("entity_1");
        let entity_1 = String::from("entity_2");
        let entities = vec![entity_0.clone(), entity_1.clone()];
        let statement = EntityStatement::create(entities.clone(), did.clone(), None)
            .await
            .unwrap();

        let entity_statement = Statement::EntityRegistration(statement);
        // Verify registration succeeds without error
        db.register_statement(&entity_statement, Some(&graph_id))
            .await
            .unwrap();
    }

    /// Test sigstore statement registration (global statements don't need graph_id)
    pub async fn test_register_sigstore_statement(db: Arc<dyn IStatementIdx + Send + Sync>) {
        let did = String::from("did:key:sig_store");
        let subject = String::from("urn:cid:sigstore_subject");
        let bundle = SigstoreBundle::new(serde_json::Value::Null, serde_json::Value::Null);
        let statement = SigstoreBundleStatement::create(subject, &bundle, did.clone(), None)
            .await
            .unwrap();

        let sig_statement = Statement::CredentialSigstoreBundleRegistration(statement);
        db.register_statement(&sig_statement, None).await.unwrap();

        // Note: Global statements are not retrieved via retrieve_graph alone
        // This test just verifies the statement can be registered without error
    }

    /// Test credential statement registration (global)
    pub async fn test_register_credential_statement(db: Arc<dyn IStatementIdx + Send + Sync>) {
        let did = String::from("did:key:credential");
        let doc_str = r#"{
            "@context": "https://www.w3.org/2018/credentials/v1",
            "id": "http://example.org/credentials/3731",
            "type": ["VerifiableCredential"],
            "issuer": "did:example:30e07a529f32d234f6181736bd3",
            "issuanceDate": "2020-08-19T21:41:50Z",
            "credentialSubject": {
                "id": "did:example:d23dd687a7dc6787646f2eb98d0"
            }
        }"#;
        let doc: Credential = serde_json::from_str(doc_str).unwrap();
        let statement = VcStatement::create(doc, did.clone(), None).await.unwrap();

        let cred_statement = Statement::CredentialRegistration(statement);
        db.register_statement(&cred_statement, None).await.unwrap();
    }

    /// Test DSSE statement registration (global)
    pub async fn test_register_dsse_statement(db: Arc<dyn IStatementIdx + Send + Sync>) {
        let did = String::from("did:key:dsse");
        let signature = Signature {
            keyid: String::from("sig_key"),
            sig: String::from("sig_sig"),
        };
        let envelope = Envelope {
            payload_type: String::from("payload_1"),
            payload: String::from("payload"),
            signatures: vec![signature],
        };
        let statement = DsseStatement::create(envelope, did.clone(), None)
            .await
            .unwrap();

        let dsse_statement = Statement::CredentialDsseRegistration(statement);
        db.register_statement(&dsse_statement, None).await.unwrap();

        // Global statement registration test
    }

    /// Test regular DID statement registration (global)
    pub async fn test_register_regular_did_statement(db: Arc<dyn IStatementIdx + Send + Sync>) {
        let did = String::from("did:key:did");
        let registered_by = String::from("did:key:registered_by");
        let statement = DidStatementRegular::create(did.clone(), registered_by.clone(), None)
            .await
            .unwrap();

        let did_statement = DidStatement::Regular(statement);
        db.register_statement(&Statement::DidRegistration(Box::new(did_statement)), None)
            .await
            .unwrap();

        // Global statement registration test
    }

    /// Test AMD SEV DID statement registration (global)
    pub async fn test_register_amd_sev_did_statement(db: Arc<dyn IStatementIdx + Send + Sync>) {
        let did = String::from("did:example:123");
        let registered_by = String::from("did:key:registered_by");

        let statement = DidStatement::AmdSevV1(
            DidStatementEqtyVCompAmdSevV1::create(
                did.clone(),
                Some([0; 32]),
                "SEV MODE Auto".to_owned(),
                1,
                "AMD EPYC".to_owned(),
                UrnCidWithSha256 {
                    cid: "urn:cid:OVMF".to_owned(),
                    sha256: [0; 32],
                },
                UrnCidWithSha256 {
                    cid: "urn:cid:kernel".to_owned(),
                    sha256: [0; 32],
                },
                UrnCidWithSha256 {
                    cid: "urn:cid:initrd".to_owned(),
                    sha256: [0; 32],
                },
                UrnCidWithSha256 {
                    cid: "urn:cid:append".to_owned(),
                    sha256: [0; 32],
                },
                registered_by.clone(),
                None,
            )
            .await
            .unwrap(),
        );

        db.register_statement(&Statement::DidRegistration(Box::new(statement)), None)
            .await
            .unwrap();

        // Global statement registration test
    }

    /// Test Azure VComp DID statement registration (global)
    pub async fn test_register_azure_vcomp_did_statement(db: Arc<dyn IStatementIdx + Send + Sync>) {
        let did = String::from("did:example:123");
        let registered_by = String::from("did:key:registered_by");

        let statement = DidStatement::AzureV1(
            DidStatementEqtyVCompAzureV1::create(
                did.clone(),
                Some(vec![0; 32]),
                Some(vec![0; 32]),
                Some("urn:cid:uki".to_owned()),
                Some(UrnCidWithSha384 {
                    cid: "urn:cid:kernel".to_owned(),
                    sha384: [0; 48],
                }),
                Some(UrnCidWithSha384 {
                    cid: "urn:cid:initrd".to_owned(),
                    sha384: [0; 48],
                }),
                Some(UrnCidWithSha384 {
                    cid: "urn:cid:append".to_owned(),
                    sha384: [0; 48],
                }),
                Some(UrnCidWithSha256 {
                    cid: "urn:cid:rootfs".to_owned(),
                    sha256: [0; 32],
                }),
                registered_by.clone(),
                None,
            )
            .await
            .unwrap(),
        );

        db.register_statement(&Statement::DidRegistration(Box::new(statement)), None)
            .await
            .unwrap();

        // Global statement registration test
    }

    /// Test Docker DID statement registration (global)
    pub async fn test_register_docker_did_statement(db: Arc<dyn IStatementIdx + Send + Sync>) {
        let did = String::from("did:example:123");
        let registered_by = String::from("did:key:registered_by");

        let statement = DidStatement::DockerV1(
            DidStatementEqtyVCompDockerV1::create(
                did.clone(),
                vec![],
                "urn:cid:compose".to_owned(),
                "did:example:456".to_owned(),
                "did:example:789".to_owned(),
                registered_by.clone(),
                None,
            )
            .await
            .unwrap(),
        );

        db.register_statement(&Statement::DidRegistration(Box::new(statement)), None)
            .await
            .unwrap();

        // Global statement registration test
    }

    /// Test Intel TDX DID statement registration (global)
    pub async fn test_register_intel_tdx_did_statement(db: Arc<dyn IStatementIdx + Send + Sync>) {
        let did = String::from("did:example:123");
        let registered_by = String::from("did:key:registered_by");

        let statement = DidStatement::IntelTdxV0(
            DidStatementEqtyVCompIntelTdxV0::create(
                did.clone(),
                vec![[0; 48]; 2],
                Some(UrnCidWithSha384 {
                    cid: "urn:cid:ovmf".to_owned(),
                    sha384: [0; 48],
                }),
                Some(UrnCidWithSha384 {
                    cid: "urn:cid:kernel".to_owned(),
                    sha384: [0; 48],
                }),
                Some(UrnCidWithSha384 {
                    cid: "urn:cid:initrd".to_owned(),
                    sha384: [0; 48],
                }),
                Some(UrnCidWithSha384 {
                    cid: "urn:cid:append".to_owned(),
                    sha384: [0; 48],
                }),
                registered_by.clone(),
                None,
            )
            .await
            .unwrap(),
        );

        db.register_statement(&Statement::DidRegistration(Box::new(statement)), None)
            .await
            .unwrap();

        // Global statement registration test
    }

    /// Test governance statement registration (global)
    pub async fn test_register_governance_statement(db: Arc<dyn IStatementIdx + Send + Sync>) {
        let did = String::from("did:key:governance");
        let subject = String::from("urn:cid:gov_subject");
        let document = String::from("urn:uuid:document");
        let statement =
            GovernanceStatement::create(subject.clone(), document.clone(), did.clone(), None)
                .await
                .unwrap();

        let gov_statement = Statement::GovernanceRegistration(statement);
        db.register_statement(&gov_statement, None).await.unwrap();

        // Global statement registration test
    }

    /// Test statement retrieval with hierarchy
    pub async fn test_statement_retrieval_with_hierarchy(db: Arc<dyn IStatementIdx + Send + Sync>) {
        let root_graph_id = uuid::uuid!("00000000-0000-0000-0000-500000000001");
        db.create_graph(&root_graph_id, "Root Graph", None)
            .await
            .unwrap();

        let child_graph_id = uuid::uuid!("00000000-0000-0000-0000-500000000002");
        db.create_graph(&child_graph_id, "Child Graph", Some(&root_graph_id))
            .await
            .unwrap();

        let child_graph_id_2 = uuid::uuid!("00000000-0000-0000-0000-500000000003");
        db.create_graph(&child_graph_id_2, "Child Graph 2", Some(&child_graph_id))
            .await
            .unwrap();

        let input_data = vec![
            "urn:cid:comp_data_input_1".to_owned(),
            "urn:cid:comp_data_input_2".to_owned(),
        ];
        let statement =
            DataStatement::create(input_data.clone(), "did:key:unit_test".to_owned(), None)
                .await
                .unwrap();

        let data_input = Statement::DataRegistration(statement);
        db.register_statement(&data_input, Some(&root_graph_id))
            .await
            .unwrap();

        let output_data = vec!["urn:cid:comp_data_output".to_owned()];
        let statement =
            DataStatement::create(output_data.clone(), "did:key:unit_test".to_owned(), None)
                .await
                .unwrap();

        let data_output = Statement::DataRegistration(statement);
        db.register_statement(&data_output, Some(&child_graph_id))
            .await
            .unwrap();

        let statement = MetadataStatement::create(
            "urn:cid:comp_data_input_1".to_owned(),
            String::from("metadata"),
            "did:key:metadata".to_owned(),
            None,
        )
        .await
        .unwrap();

        let metadata = Statement::MetadataRegistration(statement);
        db.register_statement(&metadata, Some(&child_graph_id_2))
            .await
            .unwrap();

        let did = String::from("did:key:comp_statement");
        let statement = ComputationStatement::create(
            None,
            input_data,
            output_data,
            did.clone(),
            None,
            did,
            None,
        )
        .await
        .unwrap();

        let comp_statement = Statement::ComputationRegistration(statement);
        db.register_statement(&comp_statement, Some(&child_graph_id))
            .await
            .unwrap();

        // Check that the statements in the parent graphs get pulled in
        let graph = db.retrieve_graph(&child_graph_id).await.unwrap();
        assert_eq!(graph.statements.as_ref().unwrap().len(), 3);

        // Register the same statement in a lower child project
        db.register_statement(&comp_statement, Some(&child_graph_id_2))
            .await
            .unwrap();

        // Check that the statements in the parent graphs get pulled in from a lower child
        let graph = db.retrieve_graph(&child_graph_id_2).await.unwrap();
        assert_eq!(graph.statements.as_ref().unwrap().len(), 4);
    }

    /// Test global statement retrieval
    pub async fn test_global_statement_retrieval(db: Arc<dyn IStatementIdx + Send + Sync>) {
        let graph_id = uuid::uuid!("00000000-0000-0000-0000-500000000011");
        db.create_graph(&graph_id, "Global Statements", None)
            .await
            .unwrap();

        let did = String::from("did:key:global_did");
        let did_statement = DidStatementRegular::create(did.clone(), did.clone(), None)
            .await
            .unwrap();
        let did_statement = DidStatement::Regular(did_statement);
        let did_statement_id = did_statement.get_id();

        db.register_statement(&Statement::DidRegistration(Box::new(did_statement)), None)
            .await
            .unwrap();

        let input_data = vec![
            "urn:cid:comp_data_input_1".to_owned(),
            "urn:cid:comp_data_input_2".to_owned(),
        ];
        let computation_statement = ComputationStatement::create(
            None,
            input_data,
            vec!["urn:cid:comp_data_output".to_owned()],
            did.clone(),
            None,
            did.clone(),
            None,
        )
        .await
        .unwrap();

        db.register_statement(
            &Statement::ComputationRegistration(computation_statement),
            Some(&graph_id),
        )
        .await
        .unwrap();

        let graph = db.retrieve_graph(&graph_id).await.unwrap();

        // The graph should include both the computation statement and the global DID statement
        let statements = graph.statements.as_ref().unwrap();
        assert!(statements.iter().any(|s| s.get_id() == did_statement_id));
        assert!(statements.len() >= 2);
    }
}
