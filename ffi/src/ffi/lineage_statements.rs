use std::ffi::c_char;

use serde::{de::DeserializeOwned, Deserialize};
use serde_json::Value;
use ssi::vc::Credential;

use crate::{
    ffi::{
        error::{map_anyhow, run_ffi, FfiError, IgStatus},
        runtime::IgRuntimeHandle,
        util::{as_ref, cstr_to_string, write_c_string},
    },
    lineage::models::{
        dsse::Envelope as LineageDsseEnvelope,
        statements::{
            common::{UrnCidWithSha256, UrnCidWithSha384},
            did_statement::{
                DidStatementEqtyVCompAmdSevV1, DidStatementEqtyVCompAzureV1,
                DidStatementEqtyVCompCustomV1, DidStatementEqtyVCompDockerV1,
                DidStatementEqtyVCompIntelTdxV0, DidStatementRegular,
            },
            extract_statement_id, extract_statement_type, AssociationStatement, AssociationType,
            ComputationStatement, DataStatement, DsseStatement, EntityStatement,
            GovernanceStatement, MetadataStatement, SigstoreBundleStatement, Statement,
            StatementTrait, StorageStatement, VcStatement,
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

fn decode_hex_vec(
    hex_value: Option<String>,
    field_name: &str,
) -> Result<Option<Vec<u8>>, FfiError> {
    match hex_value {
        Some(value) => {
            let bytes = hex::decode(value).map_err(|e| {
                FfiError::new(
                    IgStatus::InvalidInput,
                    format!("failed to decode {field_name} hex: {e}"),
                )
            })?;
            Ok(Some(bytes))
        }
        None => Ok(None),
    }
}

fn decode_hex_arr<const N: usize>(value: String, field_name: &str) -> Result<[u8; N], FfiError> {
    let bytes = hex::decode(value).map_err(|e| {
        FfiError::new(
            IgStatus::InvalidInput,
            format!("failed to decode {field_name} hex: {e}"),
        )
    })?;

    bytes.try_into().map_err(|_| {
        FfiError::new(
            IgStatus::InvalidInput,
            format!("{field_name} must decode to {N} bytes"),
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

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DidAmdSevV1CreateRequest {
    did: String,
    measurement: Option<String>,
    sev_mode: String,
    num_cpu_cores: u32,
    cpu_type: String,
    ovmf: UrnCidWithSha256,
    kernel: UrnCidWithSha256,
    initrd: UrnCidWithSha256,
    append: UrnCidWithSha256,
    registered_by: String,
    timestamp: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DidAzureV1CreateRequest {
    did: String,
    pcr11: Option<String>,
    firmware: Option<String>,
    uki: Option<String>,
    kernel: Option<UrnCidWithSha384>,
    initrd: Option<UrnCidWithSha384>,
    append: Option<UrnCidWithSha384>,
    rootfs: Option<UrnCidWithSha256>,
    registered_by: String,
    timestamp: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DidCustomV1CreateRequest {
    did: String,
    value: Value,
    registered_by: String,
    timestamp: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DockerImage {
    name: String,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DidDockerV1CreateRequest {
    did: String,
    image: Vec<DockerImage>,
    compose: String,
    operated_by: String,
    executed_on: String,
    registered_by: String,
    timestamp: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DidIntelTdxV0CreateRequest {
    did: String,
    measurements: Vec<String>,
    ovmf: Option<UrnCidWithSha384>,
    kernel: Option<UrnCidWithSha384>,
    initrd: Option<UrnCidWithSha384>,
    append: Option<UrnCidWithSha384>,
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
pub extern "C" fn ig_lineage_statement_create_did_amdsev_v1(
    runtime: *const IgRuntimeHandle,
    request_json: *const c_char,
    out_statement_json: *mut *mut c_char,
    err_out: *mut *mut c_char,
) -> IgStatus {
    run_ffi(err_out, || {
        let runtime = as_ref(runtime, "runtime")?;
        let request_json = cstr_to_string(request_json, "request_json")?;
        let request: DidAmdSevV1CreateRequest =
            parse_request(request_json, "did amdsev v1 request")?;

        let measurement = match request.measurement {
            Some(value) => Some(decode_hex_arr::<32>(value, "measurement")?),
            None => None,
        };

        let statement = map_anyhow(runtime.block_on(DidStatementEqtyVCompAmdSevV1::create(
            request.did,
            measurement,
            request.sev_mode,
            request.num_cpu_cores,
            request.cpu_type,
            request.ovmf,
            request.kernel,
            request.initrd,
            request.append,
            request.registered_by,
            request.timestamp,
        )))?;

        let statement_json = map_anyhow(serde_json::to_string(&statement).map_err(Into::into))?;
        write_c_string(out_statement_json, statement_json, "out_statement_json")
    })
}

#[no_mangle]
pub extern "C" fn ig_lineage_statement_create_did_azure_v1(
    runtime: *const IgRuntimeHandle,
    request_json: *const c_char,
    out_statement_json: *mut *mut c_char,
    err_out: *mut *mut c_char,
) -> IgStatus {
    run_ffi(err_out, || {
        let runtime = as_ref(runtime, "runtime")?;
        let request_json = cstr_to_string(request_json, "request_json")?;
        let request: DidAzureV1CreateRequest = parse_request(request_json, "did azure v1 request")?;

        let pcr11 = decode_hex_vec(request.pcr11, "pcr11")?;
        let firmware = decode_hex_vec(request.firmware, "firmware")?;

        let statement = map_anyhow(runtime.block_on(DidStatementEqtyVCompAzureV1::create(
            request.did,
            pcr11,
            firmware,
            request.uki,
            request.kernel,
            request.initrd,
            request.append,
            request.rootfs,
            request.registered_by,
            request.timestamp,
        )))?;

        let statement_json = map_anyhow(serde_json::to_string(&statement).map_err(Into::into))?;
        write_c_string(out_statement_json, statement_json, "out_statement_json")
    })
}

#[no_mangle]
pub extern "C" fn ig_lineage_statement_create_did_custom_v1(
    runtime: *const IgRuntimeHandle,
    request_json: *const c_char,
    out_statement_json: *mut *mut c_char,
    err_out: *mut *mut c_char,
) -> IgStatus {
    run_ffi(err_out, || {
        let runtime = as_ref(runtime, "runtime")?;
        let request_json = cstr_to_string(request_json, "request_json")?;
        let request: DidCustomV1CreateRequest =
            parse_request(request_json, "did custom v1 request")?;

        let statement = map_anyhow(runtime.block_on(DidStatementEqtyVCompCustomV1::create(
            request.did,
            request.value,
            request.registered_by,
            request.timestamp,
        )))?;

        let statement_json = map_anyhow(serde_json::to_string(&statement).map_err(Into::into))?;
        write_c_string(out_statement_json, statement_json, "out_statement_json")
    })
}

#[no_mangle]
pub extern "C" fn ig_lineage_statement_create_did_docker_v1(
    runtime: *const IgRuntimeHandle,
    request_json: *const c_char,
    out_statement_json: *mut *mut c_char,
    err_out: *mut *mut c_char,
) -> IgStatus {
    run_ffi(err_out, || {
        let runtime = as_ref(runtime, "runtime")?;
        let request_json = cstr_to_string(request_json, "request_json")?;
        let request: DidDockerV1CreateRequest =
            parse_request(request_json, "did docker v1 request")?;

        let image = request
            .image
            .into_iter()
            .map(|entry| (entry.name, entry.sha256))
            .collect();

        let statement = map_anyhow(runtime.block_on(DidStatementEqtyVCompDockerV1::create(
            request.did,
            image,
            request.compose,
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
pub extern "C" fn ig_lineage_statement_create_did_inteltdx_v0(
    runtime: *const IgRuntimeHandle,
    request_json: *const c_char,
    out_statement_json: *mut *mut c_char,
    err_out: *mut *mut c_char,
) -> IgStatus {
    run_ffi(err_out, || {
        let runtime = as_ref(runtime, "runtime")?;
        let request_json = cstr_to_string(request_json, "request_json")?;
        let request: DidIntelTdxV0CreateRequest =
            parse_request(request_json, "did inteltdx v0 request")?;

        let measurements = request
            .measurements
            .into_iter()
            .map(|value| decode_hex_arr::<48>(value, "measurement"))
            .collect::<Result<Vec<_>, _>>()?;

        let statement = map_anyhow(runtime.block_on(DidStatementEqtyVCompIntelTdxV0::create(
            request.did,
            measurements,
            request.ovmf,
            request.kernel,
            request.initrd,
            request.append,
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

#[cfg(test)]
mod tests {
    use std::{
        ffi::{c_char, CStr, CString},
        ptr,
    };

    use serde_json::Value;

    use super::*;
    use crate::ffi::{error::IgStatus, runtime};

    fn cstring(s: &str) -> CString {
        CString::new(s).expect("test string has no NUL")
    }

    fn take_owned_c_string(ptr: *mut c_char) -> String {
        assert!(!ptr.is_null(), "expected non-null C string pointer");
        let s = unsafe { CStr::from_ptr(ptr) }
            .to_str()
            .expect("valid utf-8")
            .to_owned();
        unsafe {
            super::super::ig_string_free(ptr);
        }
        s
    }

    fn assert_ok(status: IgStatus, err: *mut c_char) {
        if status == IgStatus::Ok {
            assert!(err.is_null(), "expected null err_out on success");
            return;
        }
        let msg = if err.is_null() {
            String::from("<no error message>")
        } else {
            let s = unsafe { CStr::from_ptr(err) }
                .to_str()
                .expect("valid utf-8")
                .to_owned();
            unsafe { super::super::ig_error_free(err) };
            s
        };
        panic!("expected IgStatus::Ok, got {:?}: {}", status, msg);
    }

    fn new_runtime() -> *mut runtime::IgRuntimeHandle {
        let mut handle = ptr::null_mut();
        let mut err_out = ptr::null_mut();
        let status = runtime::ig_runtime_new(&mut handle, &mut err_out);
        assert_ok(status, err_out);
        handle
    }

    const REGISTERED_BY: &str = "did:key:z6Mkw2PvzC9DHXiYQHMDRwyxCCV9n4EDc6vqqp1uyi9nrwsP";
    const TIMESTAMP: &str = "2025-01-01T00:00:00Z";
    const CID_A: &str = "bafkr4ibthuzk3zug7ghmx63yjqaiu6rx4hhfdv3453j5bodskgw57bx2ya";
    const CID_B: &str = "baga6yaq6echz7kjzuhzubnsq2mqkw5oxpkrio5nwb4fibzkwaqke3hqbc25g4";

    #[test]
    fn create_computation_smoke() {
        let runtime = new_runtime();

        let request = serde_json::json!({
            "computation": CID_A,
            "input": [CID_A],
            "output": [CID_B],
            "operatedBy": REGISTERED_BY,
            "executedOn": null,
            "registeredBy": REGISTERED_BY,
            "timestamp": TIMESTAMP
        });
        let request_c = cstring(&request.to_string());

        let mut out = ptr::null_mut();
        let mut err_out = ptr::null_mut();
        let status = ig_lineage_statement_create_computation(
            runtime,
            request_c.as_ptr(),
            &mut out,
            &mut err_out,
        );
        assert_ok(status, err_out);

        let json = take_owned_c_string(out);
        let v: Value = serde_json::from_str(&json).expect("valid json");
        assert_eq!(v["@type"], "ComputationRegistration");
        assert!(v["@id"].as_str().unwrap().starts_with("urn:cid:"));
        assert_eq!(v["registeredBy"], REGISTERED_BY);

        runtime::ig_runtime_free(runtime);
    }

    #[test]
    fn create_data_smoke() {
        let runtime = new_runtime();

        let request = serde_json::json!({
            "data": [CID_A],
            "registeredBy": REGISTERED_BY,
            "timestamp": TIMESTAMP
        });
        let request_c = cstring(&request.to_string());

        let mut out = ptr::null_mut();
        let mut err_out = ptr::null_mut();
        let status =
            ig_lineage_statement_create_data(runtime, request_c.as_ptr(), &mut out, &mut err_out);
        assert_ok(status, err_out);

        let json = take_owned_c_string(out);
        let v: Value = serde_json::from_str(&json).expect("valid json");
        assert_eq!(v["@type"], "DataRegistration");
        assert!(v["@id"].as_str().unwrap().starts_with("urn:cid:"));
        assert_eq!(v["registeredBy"], REGISTERED_BY);

        runtime::ig_runtime_free(runtime);
    }

    #[test]
    fn create_dsse_smoke() {
        let runtime = new_runtime();

        // base64("urn:cid:bafkr4ibthuzk3zug7ghmx63yjqaiu6rx4hhfdv3453j5bodskgw57bx2ya")
        let payload = "dXJuOmNpZDpiYWZrcjRpYnRodXprM3p1ZzdnaG14NjN5anFhaXU2cng0aGhmZHYzNDUzajVib2Rza2d3NTdieDJ5YQ==";

        let request = serde_json::json!({
            "envelope": {
                "payloadType": "application/vnd.in-toto+json",
                "payload": payload,
                "signatures": [{"keyid": "test-key", "sig": "dGVzdA=="}]
            },

            "registeredBy": REGISTERED_BY,
            "timestamp": TIMESTAMP
        });
        let request_c = cstring(&request.to_string());

        let mut out = ptr::null_mut();
        let mut err_out = ptr::null_mut();
        let status =
            ig_lineage_statement_create_dsse(runtime, request_c.as_ptr(), &mut out, &mut err_out);
        assert_ok(status, err_out);

        let json = take_owned_c_string(out);
        let v: Value = serde_json::from_str(&json).expect("valid json");
        assert_eq!(v["@type"], "CredentialRegistration");
        assert!(v["@id"].as_str().unwrap().starts_with("urn:cid:"));
        assert_eq!(v["registeredBy"], REGISTERED_BY);

        runtime::ig_runtime_free(runtime);
    }

    #[test]
    fn create_entity_smoke() {
        let runtime = new_runtime();

        let request = serde_json::json!({
            "entity": [CID_A],
            "registeredBy": REGISTERED_BY,
            "timestamp": TIMESTAMP
        });
        let request_c = cstring(&request.to_string());

        let mut out = ptr::null_mut();
        let mut err_out = ptr::null_mut();
        let status =
            ig_lineage_statement_create_entity(runtime, request_c.as_ptr(), &mut out, &mut err_out);
        assert_ok(status, err_out);

        let json = take_owned_c_string(out);
        let v: Value = serde_json::from_str(&json).expect("valid json");
        assert_eq!(v["@type"], "EntityRegistration");
        assert!(v["@id"].as_str().unwrap().starts_with("urn:cid:"));
        assert_eq!(v["registeredBy"], REGISTERED_BY);

        runtime::ig_runtime_free(runtime);
    }

    #[test]
    fn create_governance_smoke() {
        let runtime = new_runtime();

        let request = serde_json::json!({
            "subject": CID_A,
            "document": CID_B,
            "registeredBy": REGISTERED_BY,
            "timestamp": TIMESTAMP
        });
        let request_c = cstring(&request.to_string());

        let mut out = ptr::null_mut();
        let mut err_out = ptr::null_mut();
        let status = ig_lineage_statement_create_governance(
            runtime,
            request_c.as_ptr(),
            &mut out,
            &mut err_out,
        );
        assert_ok(status, err_out);

        let json = take_owned_c_string(out);
        let v: Value = serde_json::from_str(&json).expect("valid json");
        assert_eq!(v["@type"], "GovernanceRegistration");
        assert!(v["@id"].as_str().unwrap().starts_with("urn:cid:"));
        assert_eq!(v["registeredBy"], REGISTERED_BY);

        runtime::ig_runtime_free(runtime);
    }

    #[test]
    fn create_metadata_smoke() {
        let runtime = new_runtime();

        let request = serde_json::json!({
            "subject": CID_A,
            "metadata": CID_B,
            "registeredBy": REGISTERED_BY,
            "timestamp": TIMESTAMP
        });
        let request_c = cstring(&request.to_string());

        let mut out = ptr::null_mut();
        let mut err_out = ptr::null_mut();
        let status = ig_lineage_statement_create_metadata(
            runtime,
            request_c.as_ptr(),
            &mut out,
            &mut err_out,
        );
        assert_ok(status, err_out);

        let json = take_owned_c_string(out);
        let v: Value = serde_json::from_str(&json).expect("valid json");
        assert_eq!(v["@type"], "MetadataRegistration");
        assert!(v["@id"].as_str().unwrap().starts_with("urn:cid:"));
        assert_eq!(v["registeredBy"], REGISTERED_BY);

        runtime::ig_runtime_free(runtime);
    }

    #[test]
    fn create_metadata_from_json_smoke() {
        let runtime = new_runtime();

        let request = serde_json::json!({
            "subject": CID_A,
            "metadata": {"key": "value", "nested": {"count": 42}},
            "registeredBy": REGISTERED_BY,
            "timestamp": TIMESTAMP
        });
        let request_c = cstring(&request.to_string());

        let mut out = ptr::null_mut();
        let mut err_out = ptr::null_mut();
        let status = ig_lineage_statement_create_metadata_from_json(
            runtime,
            request_c.as_ptr(),
            &mut out,
            &mut err_out,
        );
        assert_ok(status, err_out);

        let json = take_owned_c_string(out);
        let v: Value = serde_json::from_str(&json).expect("valid json");
        assert_eq!(v["@type"], "MetadataRegistration");
        assert!(v["@id"].as_str().unwrap().starts_with("urn:cid:"));
        assert_eq!(v["registeredBy"], REGISTERED_BY);

        runtime::ig_runtime_free(runtime);
    }

    #[test]
    fn create_sigstore_bundle_smoke() {
        let runtime = new_runtime();

        let request = serde_json::json!({
            "subject": CID_A,
            "sigstoreBundle": {
                "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                "verificationMaterial": {"publicKey": {"hint": "test-hint"}},
                "dsseEnvelope": {
                    "payload": "dGVzdA==",
                    "payloadType": "application/vnd.in-toto+json",
                    "signatures": [{"keyid": "", "sig": "dGVzdA=="}]
                }
            },
            "registeredBy": REGISTERED_BY,
            "timestamp": TIMESTAMP
        });
        let request_c = cstring(&request.to_string());

        let mut out = ptr::null_mut();
        let mut err_out = ptr::null_mut();
        let status = ig_lineage_statement_create_sigstore_bundle(
            runtime,
            request_c.as_ptr(),
            &mut out,
            &mut err_out,
        );
        assert_ok(status, err_out);

        let json = take_owned_c_string(out);
        let v: Value = serde_json::from_str(&json).expect("valid json");
        assert_eq!(v["@type"], "CredentialRegistration");
        assert!(v["@id"].as_str().unwrap().starts_with("urn:cid:"));
        assert_eq!(v["registeredBy"], REGISTERED_BY);

        runtime::ig_runtime_free(runtime);
    }

    #[test]
    fn create_storage_smoke() {
        let runtime = new_runtime();

        let request = serde_json::json!({
            "data": CID_A,
            "storedOn": CID_B,
            "operatedBy": REGISTERED_BY,
            "registeredBy": REGISTERED_BY,
            "timestamp": TIMESTAMP
        });
        let request_c = cstring(&request.to_string());

        let mut out = ptr::null_mut();
        let mut err_out = ptr::null_mut();
        let status = ig_lineage_statement_create_storage(
            runtime,
            request_c.as_ptr(),
            &mut out,
            &mut err_out,
        );
        assert_ok(status, err_out);

        let json = take_owned_c_string(out);
        let v: Value = serde_json::from_str(&json).expect("valid json");
        assert_eq!(v["@type"], "StorageRegistration");
        assert!(v["@id"].as_str().unwrap().starts_with("urn:cid:"));
        assert_eq!(v["registeredBy"], REGISTERED_BY);

        runtime::ig_runtime_free(runtime);
    }

    #[test]
    fn create_vc_smoke() {
        let runtime = new_runtime();

        let request = serde_json::json!({
            "credential": {
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "type": ["VerifiableCredential"],
                "id": "urn:uuid:12345678-1234-1234-1234-123456789012",
                "issuer": REGISTERED_BY,
                "issuanceDate": "2024-01-01T00:00:00Z",
                "credentialSubject": {"id": format!("urn:cid:{CID_A}")}
            },
            "registeredBy": REGISTERED_BY,
            "timestamp": TIMESTAMP
        });
        let request_c = cstring(&request.to_string());

        let mut out = ptr::null_mut();
        let mut err_out = ptr::null_mut();
        let status =
            ig_lineage_statement_create_vc(runtime, request_c.as_ptr(), &mut out, &mut err_out);
        assert_ok(status, err_out);

        let json = take_owned_c_string(out);
        let v: Value = serde_json::from_str(&json).expect("valid json");
        assert_eq!(v["@type"], "CredentialRegistration");
        assert!(v["@id"].as_str().unwrap().starts_with("urn:cid:"));
        assert_eq!(v["registeredBy"], REGISTERED_BY);

        runtime::ig_runtime_free(runtime);
    }

    #[test]
    fn create_did_amdsev_v1_smoke() {
        let runtime = new_runtime();

        let sha256_hex = hex::encode([0xabu8; 32]);
        let request = serde_json::json!({
            "did": REGISTERED_BY,
            "measurement": hex::encode([0x00u8; 32]),
            "sevMode": "snp",
            "numCpuCores": 4,
            "cpuType": "EPYC",
            "ovmf":   {"@id": format!("urn:cid:{CID_A}"), "sha256": sha256_hex},
            "kernel": {"@id": format!("urn:cid:{CID_A}"), "sha256": sha256_hex},
            "initrd": {"@id": format!("urn:cid:{CID_A}"), "sha256": sha256_hex},
            "append": {"@id": format!("urn:cid:{CID_A}"), "sha256": sha256_hex},
            "registeredBy": REGISTERED_BY,
            "timestamp": TIMESTAMP
        });
        let request_c = cstring(&request.to_string());

        let mut out = ptr::null_mut();
        let mut err_out = ptr::null_mut();
        let status = ig_lineage_statement_create_did_amdsev_v1(
            runtime,
            request_c.as_ptr(),
            &mut out,
            &mut err_out,
        );
        assert_ok(status, err_out);

        let json = take_owned_c_string(out);
        let v: Value = serde_json::from_str(&json).expect("valid json");
        assert_eq!(v["@type"], "DidRegistration");
        assert!(v["@id"].as_str().unwrap().starts_with("urn:cid:"));
        assert_eq!(v["registeredBy"], REGISTERED_BY);

        runtime::ig_runtime_free(runtime);
    }

    #[test]
    fn create_did_azure_v1_smoke() {
        let runtime = new_runtime();

        let pcr11_hex = hex::encode([0xbbu8; 32]);
        let firmware_hex = hex::encode([0xccu8; 32]);
        let request = serde_json::json!({
            "did": REGISTERED_BY,
            "pcr11": pcr11_hex,
            "firmware": firmware_hex,
            "uki": null,
            "kernel": null,
            "initrd": null,
            "append": null,
            "rootfs": null,
            "registeredBy": REGISTERED_BY,
            "timestamp": TIMESTAMP
        });
        let request_c = cstring(&request.to_string());

        let mut out = ptr::null_mut();
        let mut err_out = ptr::null_mut();
        let status = ig_lineage_statement_create_did_azure_v1(
            runtime,
            request_c.as_ptr(),
            &mut out,
            &mut err_out,
        );
        assert_ok(status, err_out);

        let json = take_owned_c_string(out);
        let v: Value = serde_json::from_str(&json).expect("valid json");
        assert_eq!(v["@type"], "DidRegistration");
        assert!(v["@id"].as_str().unwrap().starts_with("urn:cid:"));
        assert_eq!(v["registeredBy"], REGISTERED_BY);

        runtime::ig_runtime_free(runtime);
    }

    #[test]
    fn create_did_custom_v1_smoke() {
        let runtime = new_runtime();

        let request = serde_json::json!({
            "did": REGISTERED_BY,
            "value": {"arbitrary": "data", "count": 7},
            "registeredBy": REGISTERED_BY,
            "timestamp": TIMESTAMP
        });
        let request_c = cstring(&request.to_string());

        let mut out = ptr::null_mut();
        let mut err_out = ptr::null_mut();
        let status = ig_lineage_statement_create_did_custom_v1(
            runtime,
            request_c.as_ptr(),
            &mut out,
            &mut err_out,
        );
        assert_ok(status, err_out);

        let json = take_owned_c_string(out);
        let v: Value = serde_json::from_str(&json).expect("valid json");
        assert_eq!(v["@type"], "DidRegistration");
        assert!(v["@id"].as_str().unwrap().starts_with("urn:cid:"));
        assert_eq!(v["registeredBy"], REGISTERED_BY);

        runtime::ig_runtime_free(runtime);
    }

    #[test]
    fn create_did_docker_v1_smoke() {
        let runtime = new_runtime();

        let request = serde_json::json!({
            "did": REGISTERED_BY,
            "image": [{"name": "myimage:latest", "sha256": hex::encode([0xddu8; 32])}],
            "compose": hex::encode([0xeeu8; 32]),
            "operatedBy": REGISTERED_BY,
            "executedOn": "did:key:z6Mkw2PvzC9DHXiYQHMDRwyxCCV9n4EDc6vqqp1uyi9nrwsP",
            "registeredBy": REGISTERED_BY,
            "timestamp": TIMESTAMP
        });
        let request_c = cstring(&request.to_string());

        let mut out = ptr::null_mut();
        let mut err_out = ptr::null_mut();
        let status = ig_lineage_statement_create_did_docker_v1(
            runtime,
            request_c.as_ptr(),
            &mut out,
            &mut err_out,
        );
        assert_ok(status, err_out);

        let json = take_owned_c_string(out);
        let v: Value = serde_json::from_str(&json).expect("valid json");
        assert_eq!(v["@type"], "DidRegistration");
        assert!(v["@id"].as_str().unwrap().starts_with("urn:cid:"));
        assert_eq!(v["registeredBy"], REGISTERED_BY);

        runtime::ig_runtime_free(runtime);
    }

    #[test]
    fn create_did_inteltdx_v0_smoke() {
        let runtime = new_runtime();

        let measurement_hex = hex::encode([0x11u8; 48]);
        let request = serde_json::json!({
            "did": REGISTERED_BY,
            "measurements": [measurement_hex],
            "ovmf": null,
            "kernel": null,
            "initrd": null,
            "append": null,
            "registeredBy": REGISTERED_BY,
            "timestamp": TIMESTAMP
        });
        let request_c = cstring(&request.to_string());

        let mut out = ptr::null_mut();
        let mut err_out = ptr::null_mut();
        let status = ig_lineage_statement_create_did_inteltdx_v0(
            runtime,
            request_c.as_ptr(),
            &mut out,
            &mut err_out,
        );
        assert_ok(status, err_out);

        let json = take_owned_c_string(out);
        let v: Value = serde_json::from_str(&json).expect("valid json");
        assert_eq!(v["@type"], "DidRegistration");
        assert!(v["@id"].as_str().unwrap().starts_with("urn:cid:"));
        assert_eq!(v["registeredBy"], REGISTERED_BY);

        runtime::ig_runtime_free(runtime);
    }

    #[test]
    fn invalid_json_returns_json_error() {
        let runtime = new_runtime();

        let bad_json = cstring("not valid json {{{");
        let mut out = ptr::null_mut();
        let mut err_out = ptr::null_mut();
        let status =
            ig_lineage_statement_create_data(runtime, bad_json.as_ptr(), &mut out, &mut err_out);

        assert_eq!(status, IgStatus::JsonError);
        assert!(out.is_null());
        if !err_out.is_null() {
            unsafe { super::super::ig_error_free(err_out) };
        }

        runtime::ig_runtime_free(runtime);
    }

    #[test]
    fn invalid_hex_returns_invalid_input() {
        let runtime = new_runtime();

        let sha256_hex = hex::encode([0xabu8; 32]);
        let request = serde_json::json!({
            "did": REGISTERED_BY,
            "measurement": "not-valid-hex",
            "sevMode": "snp",
            "numCpuCores": 4,
            "cpuType": "EPYC",
            "ovmf":   {"@id": format!("urn:cid:{CID_A}"), "sha256": sha256_hex},
            "kernel": {"@id": format!("urn:cid:{CID_A}"), "sha256": sha256_hex},
            "initrd": {"@id": format!("urn:cid:{CID_A}"), "sha256": sha256_hex},
            "append": {"@id": format!("urn:cid:{CID_A}"), "sha256": sha256_hex},
            "registeredBy": REGISTERED_BY,
            "timestamp": TIMESTAMP
        });
        let request_c = cstring(&request.to_string());

        let mut out = ptr::null_mut();
        let mut err_out = ptr::null_mut();
        let status = ig_lineage_statement_create_did_amdsev_v1(
            runtime,
            request_c.as_ptr(),
            &mut out,
            &mut err_out,
        );

        assert_eq!(status, IgStatus::InvalidInput);
        assert!(out.is_null());
        if !err_out.is_null() {
            unsafe { super::super::ig_error_free(err_out) };
        }

        runtime::ig_runtime_free(runtime);
    }
}
