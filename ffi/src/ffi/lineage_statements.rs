use std::ffi::c_char;

use integrity::vc::Credential;
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::Value;

use crate::{
    ffi::{
        error::{map_anyhow, run_ffi, FfiError, IgStatus},
        runtime::IgRuntimeHandle,
        util::{as_ref, cstr_to_string, write_c_string},
    },
    lineage::models::{
        dsse::Envelope as LineageDsseEnvelope,
        statements::{
            did_statement::DidStatementRegular, extract_statement_id, extract_statement_type,
            AssociationStatement, AssociationType, ComputationStatement, DataStatement,
            DsseStatement, EntityStatement, GovernanceStatement, MetadataStatement,
            SigstoreBundleStatement, Statement, StatementTrait, StorageStatement, VcStatement,
        },
    },
    sigstore_bundle::SigstoreBundle,
};

fn parse_request<T: DeserializeOwned>(
    request_json: String,
    request_name: &str,
) -> Result<T, FfiError> {
    serde_json::from_str(&request_json).map_err(|e| {
        FfiError::new(
            IgStatus::JsonError,
            format!("failed to parse {request_name} json: {e}"),
        )
    })
}

fn parse_statement(statement_json: String) -> Result<Statement, FfiError> {
    serde_json::from_str::<Statement>(&statement_json).map_err(|e| {
        FfiError::new(
            IgStatus::JsonError,
            format!("failed to parse statement json: {e}"),
        )
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AssociationCreateRequest {
    subject: String,
    association: Vec<String>,
    r#type: AssociationType,
    registered_by: String,
    timestamp: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ComputationCreateRequest {
    computation: Option<String>,
    input: Vec<String>,
    output: Vec<String>,
    operated_by: String,
    executed_on: Option<String>,
    registered_by: String,
    timestamp: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DataCreateRequest {
    data: Vec<String>,
    registered_by: String,
    timestamp: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DsseCreateRequest {
    envelope: LineageDsseEnvelope,
    registered_by: String,
    timestamp: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EntityCreateRequest {
    entity: Vec<String>,
    registered_by: String,
    timestamp: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GovernanceCreateRequest {
    subject: String,
    document: String,
    registered_by: String,
    timestamp: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MetadataCreateRequest {
    subject: String,
    metadata: String,
    registered_by: String,
    timestamp: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MetadataFromJsonCreateRequest {
    subject: String,
    metadata: Value,
    registered_by: String,
    timestamp: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SigstoreBundleCreateRequest {
    subject: String,
    sigstore_bundle: SigstoreBundle,
    registered_by: String,
    timestamp: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct StorageCreateRequest {
    data: String,
    stored_on: String,
    operated_by: Option<String>,
    registered_by: String,
    timestamp: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VcCreateRequest {
    credential: Value,
    registered_by: String,
    timestamp: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DidRegularCreateRequest {
    did: String,
    registered_by: String,
    timestamp: Option<String>,
}

#[no_mangle]
pub extern "C" fn ig_lineage_statement_create_association(
    runtime: *const IgRuntimeHandle,
    request_json: *const c_char,
    out_statement_json: *mut *mut c_char,
    err_out: *mut *mut c_char,
) -> IgStatus {
    run_ffi(err_out, || {
        let runtime = as_ref(runtime, "runtime")?;
        let request_json = cstr_to_string(request_json, "request_json")?;
        let request: AssociationCreateRequest = parse_request(request_json, "association request")?;

        let statement = map_anyhow(runtime.block_on(AssociationStatement::create(
            request.subject,
            request.association,
            request.r#type,
            request.registered_by,
            request.timestamp,
        )))?;

        let statement_json = map_anyhow(serde_json::to_string(&statement).map_err(Into::into))?;
        write_c_string(out_statement_json, statement_json, "out_statement_json")
    })
}

#[no_mangle]
pub extern "C" fn ig_lineage_statement_create_computation(
    runtime: *const IgRuntimeHandle,
    request_json: *const c_char,
    out_statement_json: *mut *mut c_char,
    err_out: *mut *mut c_char,
) -> IgStatus {
    run_ffi(err_out, || {
        let runtime = as_ref(runtime, "runtime")?;
        let request_json = cstr_to_string(request_json, "request_json")?;
        let request: ComputationCreateRequest = parse_request(request_json, "computation request")?;

        let statement = map_anyhow(runtime.block_on(ComputationStatement::create(
            request.computation,
            request.input,
            request.output,
            request.operated_by,
            request.executed_on,
            request.registered_by,
            request.timestamp,
        )))?;

        let statement_json = map_anyhow(serde_json::to_string(&statement).map_err(Into::into))?;
        write_c_string(out_statement_json, statement_json, "out_statement_json")
    })
}

#[no_mangle]
pub extern "C" fn ig_lineage_statement_create_data(
    runtime: *const IgRuntimeHandle,
    request_json: *const c_char,
    out_statement_json: *mut *mut c_char,
    err_out: *mut *mut c_char,
) -> IgStatus {
    run_ffi(err_out, || {
        let runtime = as_ref(runtime, "runtime")?;
        let request_json = cstr_to_string(request_json, "request_json")?;
        let request: DataCreateRequest = parse_request(request_json, "data request")?;

        let statement = map_anyhow(runtime.block_on(DataStatement::create(
            request.data,
            request.registered_by,
            request.timestamp,
        )))?;

        let statement_json = map_anyhow(serde_json::to_string(&statement).map_err(Into::into))?;
        write_c_string(out_statement_json, statement_json, "out_statement_json")
    })
}

#[no_mangle]
pub extern "C" fn ig_lineage_statement_create_dsse(
    runtime: *const IgRuntimeHandle,
    request_json: *const c_char,
    out_statement_json: *mut *mut c_char,
    err_out: *mut *mut c_char,
) -> IgStatus {
    run_ffi(err_out, || {
        let runtime = as_ref(runtime, "runtime")?;
        let request_json = cstr_to_string(request_json, "request_json")?;
        let request: DsseCreateRequest = parse_request(request_json, "dsse request")?;

        let statement = map_anyhow(runtime.block_on(DsseStatement::create(
            request.envelope,
            request.registered_by,
            request.timestamp,
        )))?;

        let statement_json = map_anyhow(serde_json::to_string(&statement).map_err(Into::into))?;
        write_c_string(out_statement_json, statement_json, "out_statement_json")
    })
}

#[no_mangle]
pub extern "C" fn ig_lineage_statement_create_entity(
    runtime: *const IgRuntimeHandle,
    request_json: *const c_char,
    out_statement_json: *mut *mut c_char,
    err_out: *mut *mut c_char,
) -> IgStatus {
    run_ffi(err_out, || {
        let runtime = as_ref(runtime, "runtime")?;
        let request_json = cstr_to_string(request_json, "request_json")?;
        let request: EntityCreateRequest = parse_request(request_json, "entity request")?;

        let statement = map_anyhow(runtime.block_on(EntityStatement::create(
            request.entity,
            request.registered_by,
            request.timestamp,
        )))?;

        let statement_json = map_anyhow(serde_json::to_string(&statement).map_err(Into::into))?;
        write_c_string(out_statement_json, statement_json, "out_statement_json")
    })
}

#[no_mangle]
pub extern "C" fn ig_lineage_statement_create_governance(
    runtime: *const IgRuntimeHandle,
    request_json: *const c_char,
    out_statement_json: *mut *mut c_char,
    err_out: *mut *mut c_char,
) -> IgStatus {
    run_ffi(err_out, || {
        let runtime = as_ref(runtime, "runtime")?;
        let request_json = cstr_to_string(request_json, "request_json")?;
        let request: GovernanceCreateRequest = parse_request(request_json, "governance request")?;

        let statement = map_anyhow(runtime.block_on(GovernanceStatement::create(
            request.subject,
            request.document,
            request.registered_by,
            request.timestamp,
        )))?;

        let statement_json = map_anyhow(serde_json::to_string(&statement).map_err(Into::into))?;
        write_c_string(out_statement_json, statement_json, "out_statement_json")
    })
}

#[no_mangle]
pub extern "C" fn ig_lineage_statement_create_metadata(
    runtime: *const IgRuntimeHandle,
    request_json: *const c_char,
    out_statement_json: *mut *mut c_char,
    err_out: *mut *mut c_char,
) -> IgStatus {
    run_ffi(err_out, || {
        let runtime = as_ref(runtime, "runtime")?;
        let request_json = cstr_to_string(request_json, "request_json")?;
        let request: MetadataCreateRequest = parse_request(request_json, "metadata request")?;

        let statement = map_anyhow(runtime.block_on(MetadataStatement::create(
            request.subject,
            request.metadata,
            request.registered_by,
            request.timestamp,
        )))?;

        let statement_json = map_anyhow(serde_json::to_string(&statement).map_err(Into::into))?;
        write_c_string(out_statement_json, statement_json, "out_statement_json")
    })
}

#[no_mangle]
pub extern "C" fn ig_lineage_statement_create_metadata_from_json(
    runtime: *const IgRuntimeHandle,
    request_json: *const c_char,
    out_statement_json: *mut *mut c_char,
    err_out: *mut *mut c_char,
) -> IgStatus {
    run_ffi(err_out, || {
        let runtime = as_ref(runtime, "runtime")?;
        let request_json = cstr_to_string(request_json, "request_json")?;
        let request: MetadataFromJsonCreateRequest =
            parse_request(request_json, "metadata-from-json request")?;

        let statement = map_anyhow(runtime.block_on(MetadataStatement::create_from_json(
            request.subject,
            request.metadata,
            request.registered_by,
            request.timestamp,
        )))?;

        let statement_json = map_anyhow(serde_json::to_string(&statement).map_err(Into::into))?;
        write_c_string(out_statement_json, statement_json, "out_statement_json")
    })
}

#[no_mangle]
pub extern "C" fn ig_lineage_statement_create_sigstore_bundle(
    runtime: *const IgRuntimeHandle,
    request_json: *const c_char,
    out_statement_json: *mut *mut c_char,
    err_out: *mut *mut c_char,
) -> IgStatus {
    run_ffi(err_out, || {
        let runtime = as_ref(runtime, "runtime")?;
        let request_json = cstr_to_string(request_json, "request_json")?;
        let request: SigstoreBundleCreateRequest =
            parse_request(request_json, "sigstore-bundle request")?;

        let statement = map_anyhow(runtime.block_on(SigstoreBundleStatement::create(
            request.subject,
            &request.sigstore_bundle,
            request.registered_by,
            request.timestamp,
        )))?;

        let statement_json = map_anyhow(serde_json::to_string(&statement).map_err(Into::into))?;
        write_c_string(out_statement_json, statement_json, "out_statement_json")
    })
}

#[no_mangle]
pub extern "C" fn ig_lineage_statement_create_storage(
    runtime: *const IgRuntimeHandle,
    request_json: *const c_char,
    out_statement_json: *mut *mut c_char,
    err_out: *mut *mut c_char,
) -> IgStatus {
    run_ffi(err_out, || {
        let runtime = as_ref(runtime, "runtime")?;
        let request_json = cstr_to_string(request_json, "request_json")?;
        let request: StorageCreateRequest = parse_request(request_json, "storage request")?;

        let statement = map_anyhow(runtime.block_on(StorageStatement::create(
            request.data,
            request.stored_on,
            request.operated_by,
            request.registered_by,
            request.timestamp,
        )))?;

        let statement_json = map_anyhow(serde_json::to_string(&statement).map_err(Into::into))?;
        write_c_string(out_statement_json, statement_json, "out_statement_json")
    })
}

#[no_mangle]
pub extern "C" fn ig_lineage_statement_create_vc(
    runtime: *const IgRuntimeHandle,
    request_json: *const c_char,
    out_statement_json: *mut *mut c_char,
    err_out: *mut *mut c_char,
) -> IgStatus {
    run_ffi(err_out, || {
        let runtime = as_ref(runtime, "runtime")?;
        let request_json = cstr_to_string(request_json, "request_json")?;
        let request: VcCreateRequest = parse_request(request_json, "vc request")?;

        let credential: Credential = serde_json::from_value(request.credential).map_err(|e| {
            FfiError::new(
                IgStatus::JsonError,
                format!("failed to parse vc credential: {e}"),
            )
        })?;

        let statement = map_anyhow(runtime.block_on(VcStatement::create(
            credential,
            request.registered_by,
            request.timestamp,
        )))?;

        let statement_json = map_anyhow(serde_json::to_string(&statement).map_err(Into::into))?;
        write_c_string(out_statement_json, statement_json, "out_statement_json")
    })
}

#[no_mangle]
pub extern "C" fn ig_lineage_statement_create_did_regular(
    runtime: *const IgRuntimeHandle,
    request_json: *const c_char,
    out_statement_json: *mut *mut c_char,
    err_out: *mut *mut c_char,
) -> IgStatus {
    run_ffi(err_out, || {
        let runtime = as_ref(runtime, "runtime")?;
        let request_json = cstr_to_string(request_json, "request_json")?;
        let request: DidRegularCreateRequest = parse_request(request_json, "did regular request")?;

        let statement = map_anyhow(runtime.block_on(DidStatementRegular::create(
            request.did,
            request.registered_by,
            request.timestamp,
        )))?;

        let statement_json = map_anyhow(serde_json::to_string(&statement).map_err(Into::into))?;
        write_c_string(out_statement_json, statement_json, "out_statement_json")
    })
}

#[no_mangle]
pub extern "C" fn ig_lineage_statement_compute_cid(
    runtime: *const IgRuntimeHandle,
    statement_json: *const c_char,
    out_cid: *mut *mut c_char,
    err_out: *mut *mut c_char,
) -> IgStatus {
    run_ffi(err_out, || {
        let runtime = as_ref(runtime, "runtime")?;
        let statement_json = cstr_to_string(statement_json, "statement_json")?;
        let statement = parse_statement(statement_json)?;

        let cid = map_anyhow(
            runtime.block_on(crate::lineage::models::statements::compute_cid(&statement)),
        )?;
        write_c_string(out_cid, cid, "out_cid")
    })
}

#[no_mangle]
pub extern "C" fn ig_lineage_statement_extract_id(
    statement_json: *const c_char,
    out_id: *mut *mut c_char,
    err_out: *mut *mut c_char,
) -> IgStatus {
    run_ffi(err_out, || {
        let statement_json = cstr_to_string(statement_json, "statement_json")?;
        let statement_value: Value = parse_request(statement_json, "statement")?;
        let statement_id = map_anyhow(extract_statement_id(&statement_value))?;
        write_c_string(out_id, statement_id, "out_id")
    })
}

#[no_mangle]
pub extern "C" fn ig_lineage_statement_extract_type(
    statement_json: *const c_char,
    out_type: *mut *mut c_char,
    err_out: *mut *mut c_char,
) -> IgStatus {
    run_ffi(err_out, || {
        let statement_json = cstr_to_string(statement_json, "statement_json")?;
        let statement_value: Value = parse_request(statement_json, "statement")?;
        let statement_type = map_anyhow(extract_statement_type(&statement_value))?;
        write_c_string(out_type, statement_type, "out_type")
    })
}

#[no_mangle]
pub extern "C" fn ig_lineage_statement_jsonld_filename(
    statement_json: *const c_char,
    out_filename: *mut *mut c_char,
    err_out: *mut *mut c_char,
) -> IgStatus {
    run_ffi(err_out, || {
        let statement_json = cstr_to_string(statement_json, "statement_json")?;
        let statement = parse_statement(statement_json)?;
        write_c_string(out_filename, statement.jsonld_filename(), "out_filename")
    })
}

#[no_mangle]
pub extern "C" fn ig_lineage_statement_referenced_cids_json(
    statement_json: *const c_char,
    out_referenced_cids_json: *mut *mut c_char,
    err_out: *mut *mut c_char,
) -> IgStatus {
    run_ffi(err_out, || {
        let statement_json = cstr_to_string(statement_json, "statement_json")?;
        let statement = parse_statement(statement_json)?;
        let cids = statement.referenced_cids();
        let cids_json = map_anyhow(serde_json::to_string(&cids).map_err(Into::into))?;
        write_c_string(
            out_referenced_cids_json,
            cids_json,
            "out_referenced_cids_json",
        )
    })
}

#[no_mangle]
pub extern "C" fn ig_lineage_statement_registered_by(
    statement_json: *const c_char,
    out_registered_by: *mut *mut c_char,
    err_out: *mut *mut c_char,
) -> IgStatus {
    run_ffi(err_out, || {
        let statement_json = cstr_to_string(statement_json, "statement_json")?;
        let statement = parse_statement(statement_json)?;
        let registered_by = statement.get_registered_by().to_owned();
        write_c_string(out_registered_by, registered_by, "out_registered_by")
    })
}
