use std::{collections::HashMap, ffi::c_char};

use serde_json::Value;

use crate::{
    ffi::{
        blob_store::IgBlobStoreHandle,
        error::{map_anyhow, run_ffi, FfiError, IgStatus},
        runtime::IgRuntimeHandle,
        util::{as_ref, cstr_to_string, optional_cstr_to_string, write_c_string},
    },
    lineage::models::{
        manifest::{self, Manifest},
        statements::Statement,
    },
};

fn parse_statements(statements_json: String) -> Result<Vec<Statement>, FfiError> {
    serde_json::from_str::<Vec<Statement>>(&statements_json).map_err(|e| {
        FfiError::new(
            IgStatus::JsonError,
            format!("failed to parse statements json: {e}"),
        )
    })
}

#[no_mangle]
pub extern "C" fn ig_lineage_manifest_generate(
    runtime: *const IgRuntimeHandle,
    include_context: bool,
    statements_json: *const c_char,
    attributes_json_or_null: *const c_char,
    blobs_json: *const c_char,
    out_manifest_json: *mut *mut c_char,
    err_out: *mut *mut c_char,
) -> IgStatus {
    run_ffi(err_out, || {
        let runtime = as_ref(runtime, "runtime")?;
        let statements_json = cstr_to_string(statements_json, "statements_json")?;
        let blobs_json = cstr_to_string(blobs_json, "blobs_json")?;

        let statements = parse_statements(statements_json)?;
        let blobs = serde_json::from_str::<HashMap<String, String>>(&blobs_json).map_err(|e| {
            FfiError::new(
                IgStatus::JsonError,
                format!("failed to parse blobs json: {e}"),
            )
        })?;

        let attributes = match optional_cstr_to_string(attributes_json_or_null)? {
            Some(attributes_json) => {
                let value = serde_json::from_str::<HashMap<String, Value>>(&attributes_json)
                    .map_err(|e| {
                        FfiError::new(
                            IgStatus::JsonError,
                            format!("failed to parse attributes json: {e}"),
                        )
                    })?;
                Some(value)
            }
            None => None,
        };

        let manifest = map_anyhow(runtime.block_on(manifest::generate_manifest(
            include_context,
            statements,
            attributes,
            blobs,
        )))?;
        let manifest_json = map_anyhow(serde_json::to_string(&manifest).map_err(Into::into))?;

        write_c_string(out_manifest_json, manifest_json, "out_manifest_json")
    })
}

#[no_mangle]
pub extern "C" fn ig_lineage_manifest_merge(
    runtime: *const IgRuntimeHandle,
    manifest_a_json: *const c_char,
    manifest_b_json: *const c_char,
    out_manifest_json: *mut *mut c_char,
    err_out: *mut *mut c_char,
) -> IgStatus {
    run_ffi(err_out, || {
        let runtime = as_ref(runtime, "runtime")?;
        let manifest_a_json = cstr_to_string(manifest_a_json, "manifest_a_json")?;
        let manifest_b_json = cstr_to_string(manifest_b_json, "manifest_b_json")?;

        let manifest_a = serde_json::from_str::<Manifest>(&manifest_a_json).map_err(|e| {
            FfiError::new(
                IgStatus::JsonError,
                format!("failed to parse manifest_a_json: {e}"),
            )
        })?;
        let manifest_b = serde_json::from_str::<Manifest>(&manifest_b_json).map_err(|e| {
            FfiError::new(
                IgStatus::JsonError,
                format!("failed to parse manifest_b_json: {e}"),
            )
        })?;

        let merged = map_anyhow(runtime.block_on(manifest::merge_async(manifest_a, manifest_b)))?;
        let merged_json = map_anyhow(serde_json::to_string(&merged).map_err(Into::into))?;
        write_c_string(out_manifest_json, merged_json, "out_manifest_json")
    })
}

#[no_mangle]
pub extern "C" fn ig_lineage_manifest_resolve_blobs(
    runtime: *const IgRuntimeHandle,
    statements_json: *const c_char,
    store: *const IgBlobStoreHandle,
    concurrency_limit: u32,
    out_blobs_json: *mut *mut c_char,
    err_out: *mut *mut c_char,
) -> IgStatus {
    run_ffi(err_out, || {
        let runtime = as_ref(runtime, "runtime")?;
        let store = as_ref(store, "store")?;
        let statements_json = cstr_to_string(statements_json, "statements_json")?;
        let statements = parse_statements(statements_json)?;

        if concurrency_limit == 0 {
            return Err(FfiError::new(
                IgStatus::InvalidInput,
                "concurrency_limit must be greater than 0",
            ));
        }

        let blobs = map_anyhow(runtime.block_on(manifest::resolve_blobs(
            &statements,
            store.store.clone(),
            concurrency_limit as usize,
        )))?;

        let blobs_json = map_anyhow(serde_json::to_string(&blobs).map_err(Into::into))?;
        write_c_string(out_blobs_json, blobs_json, "out_blobs_json")
    })
}
