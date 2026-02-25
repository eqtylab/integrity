use std::ffi::c_char;

use ssi::vc::Credential;

use crate::{
    ffi::{
        error::{map_anyhow, run_ffi, FfiError, IgStatus},
        runtime::IgRuntimeHandle,
        signer::IgSignerHandle,
        util::{as_ref, cstr_to_string, write_bool, write_c_string},
    },
    vc,
};

#[no_mangle]
pub extern "C" fn ig_vc_issue(
    runtime: *const IgRuntimeHandle,
    signer: *const IgSignerHandle,
    subject: *const c_char,
    out_credential_json: *mut *mut c_char,
    err_out: *mut *mut c_char,
) -> IgStatus {
    run_ffi(err_out, || {
        let runtime = as_ref(runtime, "runtime")?;
        let signer = as_ref(signer, "signer")?;
        let subject = cstr_to_string(subject, "subject")?;

        let credential =
            map_anyhow(runtime.block_on(vc::issue_vc(&subject, signer.signer.clone())))?;
        let credential_json = map_anyhow(serde_json::to_string(&credential).map_err(Into::into))?;

        write_c_string(out_credential_json, credential_json, "out_credential_json")
    })
}

#[no_mangle]
pub extern "C" fn ig_vc_sign(
    runtime: *const IgRuntimeHandle,
    signer: *const IgSignerHandle,
    unsigned_credential_json: *const c_char,
    out_signed_credential_json: *mut *mut c_char,
    err_out: *mut *mut c_char,
) -> IgStatus {
    run_ffi(err_out, || {
        let runtime = as_ref(runtime, "runtime")?;
        let signer = as_ref(signer, "signer")?;
        let unsigned_credential_json =
            cstr_to_string(unsigned_credential_json, "unsigned_credential_json")?;

        let unsigned_credential = Credential::from_json_unsigned(&unsigned_credential_json)
            .map_err(|e| {
                FfiError::new(IgStatus::InvalidInput, format!("invalid unsigned vc: {e}"))
            })?;

        let signed =
            map_anyhow(runtime.block_on(vc::sign_vc(&unsigned_credential, signer.signer.clone())))?;
        let signed_json = map_anyhow(serde_json::to_string(&signed).map_err(Into::into))?;

        write_c_string(
            out_signed_credential_json,
            signed_json,
            "out_signed_credential_json",
        )
    })
}

#[no_mangle]
pub extern "C" fn ig_vc_verify(
    runtime: *const IgRuntimeHandle,
    credential_json: *const c_char,
    out_verify_result_json: *mut *mut c_char,
    out_valid: *mut bool,
    err_out: *mut *mut c_char,
) -> IgStatus {
    run_ffi(err_out, || {
        let runtime = as_ref(runtime, "runtime")?;
        let credential_json = cstr_to_string(credential_json, "credential_json")?;

        let result = map_anyhow(runtime.block_on(vc::verify_vc(&credential_json)))?;
        write_c_string(out_verify_result_json, result, "out_verify_result_json")?;
        write_bool(out_valid, true, "out_valid")?;
        Ok(())
    })
}
