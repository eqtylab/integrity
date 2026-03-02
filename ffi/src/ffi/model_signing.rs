use std::{collections::HashMap, ffi::c_char};

use serde_json::Value;

use crate::{
    ffi::{
        error::{map_anyhow, run_ffi, FfiError, IgStatus},
        runtime::IgRuntimeHandle,
        util::{as_ref, cstr_to_string, optional_cstr_to_string, write_c_string},
    },
    model_signing::{self, DirectoryInfo},
};

#[no_mangle]
pub extern "C" fn ig_model_signing_create_intoto_statement_from_hashes(
    runtime: *const IgRuntimeHandle,
    model_name: *const c_char,
    path_hashes_json: *const c_char,
    allow_symlinks: bool,
    ignore_paths_json_or_null: *const c_char,
    out_statement_json: *mut *mut c_char,
    err_out: *mut *mut c_char,
) -> IgStatus {
    run_ffi(err_out, || {
        let runtime = as_ref(runtime, "runtime")?;
        let model_name = cstr_to_string(model_name, "model_name")?;
        let path_hashes_json = cstr_to_string(path_hashes_json, "path_hashes_json")?;

        let path_hashes_hex = serde_json::from_str::<HashMap<String, String>>(&path_hashes_json)
            .map_err(|e| {
                FfiError::new(
                    IgStatus::JsonError,
                    format!("failed to parse path_hashes_json: {e}"),
                )
            })?;

        let mut path_hashes = HashMap::with_capacity(path_hashes_hex.len());
        for (path, digest_hex) in path_hashes_hex {
            let digest_bytes = hex::decode(digest_hex).map_err(|e| {
                FfiError::new(
                    IgStatus::InvalidInput,
                    format!("failed to decode hex digest for '{path}': {e}"),
                )
            })?;

            if digest_bytes.len() != 32 {
                return Err(FfiError::new(
                    IgStatus::InvalidInput,
                    format!(
                        "digest for '{path}' must be 32 bytes, got {}",
                        digest_bytes.len()
                    ),
                ));
            }

            let digest: [u8; 32] = digest_bytes.try_into().map_err(|_| {
                FfiError::new(
                    IgStatus::InvalidInput,
                    format!("invalid digest length for '{path}'"),
                )
            })?;

            path_hashes.insert(path, digest);
        }

        let ignore_paths = match optional_cstr_to_string(ignore_paths_json_or_null)? {
            Some(json) => serde_json::from_str::<Vec<String>>(&json).map_err(|e| {
                FfiError::new(
                    IgStatus::JsonError,
                    format!("failed to parse ignore_paths_json: {e}"),
                )
            })?,
            None => Vec::new(),
        };

        let statement = map_anyhow(runtime.block_on(
            model_signing::create_model_signing_intoto_statement(
                model_name,
                DirectoryInfo::PathHashMap(path_hashes),
                allow_symlinks,
                ignore_paths,
            ),
        ))?;

        let statement_json = map_anyhow(statement.into_json_string())?;
        write_c_string(out_statement_json, statement_json, "out_statement_json")
    })
}

#[no_mangle]
pub extern "C" fn ig_model_signing_create_sigstore_bundle(
    dsse_json: *const c_char,
    signer_did_key: *const c_char,
    out_sigstore_bundle_json: *mut *mut c_char,
    err_out: *mut *mut c_char,
) -> IgStatus {
    run_ffi(err_out, || {
        let dsse_json = cstr_to_string(dsse_json, "dsse_json")?;
        let signer_did_key = cstr_to_string(signer_did_key, "signer_did_key")?;

        let dsse = serde_json::from_str::<Value>(&dsse_json).map_err(|e| {
            FfiError::new(
                IgStatus::JsonError,
                format!("failed to parse dsse json: {e}"),
            )
        })?;

        let bundle = map_anyhow(model_signing::create_model_signing_sigstore_bundle(
            dsse,
            &signer_did_key,
        ))?;
        let bundle_json = map_anyhow(serde_json::to_string(&bundle).map_err(Into::into))?;

        write_c_string(
            out_sigstore_bundle_json,
            bundle_json,
            "out_sigstore_bundle_json",
        )
    })
}
