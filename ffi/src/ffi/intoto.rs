use std::{collections::HashMap, ffi::c_char, sync::Arc};

use crate::{
    ffi::{
        error::{map_anyhow, run_ffi, FfiError, IgStatus},
        runtime::IgRuntimeHandle,
        signer::IgSignerHandle,
        util::{as_ref, cstr_to_string, write_bool, write_c_string},
    },
    intoto_attestation::{self, models},
    signer::Signer,
};

#[no_mangle]
pub extern "C" fn ig_intoto_sign_statement(
    runtime: *const IgRuntimeHandle,
    signer: *const IgSignerHandle,
    statement_json: *const c_char,
    out_dsse_envelope_json: *mut *mut c_char,
    err_out: *mut *mut c_char,
) -> IgStatus {
    run_ffi(err_out, || {
        let runtime = as_ref(runtime, "runtime")?;
        let signer = as_ref(signer, "signer")?;
        let statement_json = cstr_to_string(statement_json, "statement_json")?;

        let statement_model =
            serde_json::from_str::<models::Statement>(&statement_json).map_err(|e| {
                FfiError::new(
                    IgStatus::JsonError,
                    format!("failed to parse in-toto statement json: {e}"),
                )
            })?;
        let statement = map_anyhow(crate::intoto_attestation::Statement::try_from(
            statement_model,
        ))?;

        let signer_arc: Arc<dyn Signer> = Arc::new(signer.signer.clone());
        let envelope_json = map_anyhow(runtime.block_on(
            intoto_attestation::sign_intoto_attestation(statement, signer_arc),
        ))?;

        write_c_string(
            out_dsse_envelope_json,
            envelope_json,
            "out_dsse_envelope_json",
        )
    })
}

#[no_mangle]
pub extern "C" fn ig_intoto_verify_envelope(
    runtime: *const IgRuntimeHandle,
    dsse_envelope_json: *const c_char,
    out_valid: *mut bool,
    err_out: *mut *mut c_char,
) -> IgStatus {
    run_ffi(err_out, || {
        let runtime = as_ref(runtime, "runtime")?;
        let dsse_envelope_json = cstr_to_string(dsse_envelope_json, "dsse_envelope_json")?;

        let is_valid = map_anyhow(runtime.block_on(
            intoto_attestation::verify_intoto_attestation(&dsse_envelope_json),
        ))?;
        write_bool(out_valid, is_valid, "out_valid")
    })
}

#[no_mangle]
pub extern "C" fn ig_intoto_digest_from_cid(
    cid: *const c_char,
    out_digest_json: *mut *mut c_char,
    err_out: *mut *mut c_char,
) -> IgStatus {
    run_ffi(err_out, || {
        let cid = cstr_to_string(cid, "cid")?;

        let digest_map: HashMap<String, String> =
            map_anyhow(intoto_attestation::digest_from_cid(&cid))?;
        let digest_json = map_anyhow(serde_json::to_string(&digest_map).map_err(Into::into))?;

        write_c_string(out_digest_json, digest_json, "out_digest_json")
    })
}
