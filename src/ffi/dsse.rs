use std::{ffi::c_char, str::FromStr, sync::Arc};

use crate::{
    dsse::{self, PayloadType},
    ffi::{
        error::{map_anyhow, run_ffi, FfiError, IgStatus},
        runtime::IgRuntimeHandle,
        signer::IgSignerHandle,
        util::{as_ref, bytes_from_raw, cstr_to_string, write_c_string},
    },
    signer::Signer,
};

#[no_mangle]
pub extern "C" fn ig_dsse_sign(
    runtime: *const IgRuntimeHandle,
    signer: *const IgSignerHandle,
    payload_ptr: *const u8,
    payload_len: usize,
    payload_type: *const c_char,
    out_envelope_json: *mut *mut c_char,
    err_out: *mut *mut c_char,
) -> IgStatus {
    run_ffi(err_out, || {
        let runtime = as_ref(runtime, "runtime")?;
        let signer = as_ref(signer, "signer")?;
        let payload = bytes_from_raw(payload_ptr, payload_len, "payload_ptr")?;
        let payload_type = cstr_to_string(payload_type, "payload_type")?;
        let payload_type = map_anyhow(PayloadType::from_str(&payload_type))?;

        let signer_arc: Arc<dyn Signer> = Arc::new(signer.signer.clone());
        let envelope = map_anyhow(runtime.block_on(dsse::sign_dsse(
            payload,
            payload_type,
            Some(signer_arc),
            None,
        )))?;

        let envelope_json = map_anyhow(envelope.into_json_string())?;
        write_c_string(out_envelope_json, envelope_json, "out_envelope_json")
    })
}

#[no_mangle]
pub extern "C" fn ig_dsse_sign_integrity_statement(
    runtime: *const IgRuntimeHandle,
    signer: *const IgSignerHandle,
    statement_cid: *const c_char,
    out_envelope_json: *mut *mut c_char,
    err_out: *mut *mut c_char,
) -> IgStatus {
    run_ffi(err_out, || {
        let runtime = as_ref(runtime, "runtime")?;
        let signer = as_ref(signer, "signer")?;
        let statement_cid = cstr_to_string(statement_cid, "statement_cid")?;
        let signer_arc: Arc<dyn Signer> = Arc::new(signer.signer.clone());

        let envelope = map_anyhow(runtime.block_on(dsse::sign_integrity_statement_dsse(
            statement_cid,
            Some(signer_arc),
            None,
        )))?;

        let envelope_json = map_anyhow(envelope.into_json_string())?;
        write_c_string(out_envelope_json, envelope_json, "out_envelope_json")
    })
}

#[no_mangle]
pub extern "C" fn ig_dsse_verify(
    _runtime: *const IgRuntimeHandle,
    _envelope_json: *const c_char,
    _out_valid: *mut bool,
    err_out: *mut *mut c_char,
) -> IgStatus {
    run_ffi(err_out, || {
        Err(FfiError::new(
            IgStatus::NotSupported,
            "DSSE verify is not implemented in the Rust core yet",
        ))
    })
}
