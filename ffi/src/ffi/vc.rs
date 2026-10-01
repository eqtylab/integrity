use std::{collections::HashMap, ffi::c_char};

use integrity::vc::Credential as JsonCredential;

use crate::{
    ffi::{
        error::{map_anyhow, run_ffi, FfiError, IgStatus},
        runtime::IgRuntimeHandle,
        signer::IgSignerHandle,
        util::{as_ref, cstr_to_string, optional_cstr_to_string, write_bool, write_c_string},
    },
    vc,
};

/// Parse the nullable `contexts_json` argument shared by the sign and verify
/// entry points: a JSON object mapping a context URL to the JSON-LD context
/// document served there. `NULL` means no additional contexts.
fn parse_contexts(ptr: *const c_char) -> Result<Option<HashMap<String, String>>, FfiError> {
    let Some(text) = optional_cstr_to_string(ptr)? else {
        return Ok(None);
    };

    // Values arrive as context documents, not as pre-serialized strings, so
    // each one is re-serialized to the text the JSON-LD loader expects.
    let parsed: HashMap<String, serde_json::Value> = serde_json::from_str(&text).map_err(|e| {
        FfiError::new(
            IgStatus::InvalidInput,
            format!("contexts_json must be a JSON object of url to context document: {e}"),
        )
    })?;

    Ok(Some(
        parsed
            .into_iter()
            .map(|(url, doc)| (url, doc.to_string()))
            .collect(),
    ))
}

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
pub extern "C" fn ig_vc_issue_revocable(
    runtime: *const IgRuntimeHandle,
    signer: *const IgSignerHandle,
    subject: *const c_char,
    status_server_url: *const c_char,
    status_server_jwt: *const c_char,
    out_credential_json: *mut *mut c_char,
    err_out: *mut *mut c_char,
) -> IgStatus {
    run_ffi(err_out, || {
        let runtime = as_ref(runtime, "runtime")?;
        let signer = as_ref(signer, "signer")?;
        let subject = cstr_to_string(subject, "subject")?;
        let status_server_url = cstr_to_string(status_server_url, "status_server_url")?;
        let status_server_jwt = cstr_to_string(status_server_jwt, "status_server_jwt")?;

        let credential = map_anyhow(runtime.block_on(vc::issue_revocable_vc(
            &subject,
            signer.signer.clone(),
            &status_server_url,
            &status_server_jwt,
        )))?;
        let credential_json = map_anyhow(serde_json::to_string(&credential).map_err(Into::into))?;

        write_c_string(out_credential_json, credential_json, "out_credential_json")
    })
}

#[no_mangle]
pub extern "C" fn ig_vc_sign(
    runtime: *const IgRuntimeHandle,
    signer: *const IgSignerHandle,
    unsigned_credential_json: *const c_char,
    contexts_json: *const c_char,
    out_signed_credential_json: *mut *mut c_char,
    err_out: *mut *mut c_char,
) -> IgStatus {
    run_ffi(err_out, || {
        let runtime = as_ref(runtime, "runtime")?;
        let signer = as_ref(signer, "signer")?;
        let unsigned_credential_json =
            cstr_to_string(unsigned_credential_json, "unsigned_credential_json")?;
        let contexts = parse_contexts(contexts_json)?;

        let unsigned_credential = serde_json::from_str::<JsonCredential>(&unsigned_credential_json)
            .map_err(|e| {
                FfiError::new(IgStatus::InvalidInput, format!("invalid unsigned vc: {e}"))
            })?;

        let signed = map_anyhow(runtime.block_on(vc::sign_vc(
            unsigned_credential,
            signer.signer.clone(),
            contexts,
        )))?;
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
    contexts_json: *const c_char,
    out_verify_result_json: *mut *mut c_char,
    out_valid: *mut bool,
    err_out: *mut *mut c_char,
) -> IgStatus {
    run_ffi(err_out, || {
        let runtime = as_ref(runtime, "runtime")?;
        let credential_json = cstr_to_string(credential_json, "credential_json")?;
        let contexts = parse_contexts(contexts_json)?;

        let result = map_anyhow(runtime.block_on(vc::verify_vc(&credential_json, contexts)))?;
        write_c_string(out_verify_result_json, result, "out_verify_result_json")?;
        write_bool(out_valid, true, "out_valid")?;
        Ok(())
    })
}

/// Like `ig_vc_verify`, but judges the credential's `validFrom` / `validUntil`
/// at `at_rfc3339` (an RFC 3339 time; `NULL` means now), and reports why a
/// credential was not accepted. On failure `*out_reason`, when `out_reason` is
/// not `NULL`, is set to a reason code (`expired`, `not_yet_valid`,
/// `invalid_claims`, `invalid_signature`, `invalid_proof`, `unverifiable`,
/// `legacy_rejected`) for the caller to free, or to `NULL` when the failure is
/// not a verdict on the credential. On success it is set to `NULL`.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub extern "C" fn ig_vc_verify_at(
    runtime: *const IgRuntimeHandle,
    credential_json: *const c_char,
    contexts_json: *const c_char,
    at_rfc3339: *const c_char,
    out_verify_result_json: *mut *mut c_char,
    out_valid: *mut bool,
    out_reason: *mut *mut c_char,
    err_out: *mut *mut c_char,
) -> IgStatus {
    if !out_reason.is_null() {
        unsafe { *out_reason = std::ptr::null_mut() };
    }
    run_ffi(err_out, || {
        let runtime = as_ref(runtime, "runtime")?;
        let credential_json = cstr_to_string(credential_json, "credential_json")?;
        let contexts = parse_contexts(contexts_json)?;
        let at = optional_cstr_to_string(at_rfc3339)?
            .map(|t| {
                chrono::DateTime::parse_from_rfc3339(&t)
                    .map(|d| d.with_timezone(&chrono::Utc))
                    .map_err(|e| {
                        FfiError::new(
                            IgStatus::InvalidInput,
                            format!("at_rfc3339 is not an RFC 3339 time: {e}"),
                        )
                    })
            })
            .transpose()?;

        let outcome = match at {
            Some(at) => runtime.block_on(vc::verify_vc_at(&credential_json, contexts, at)),
            None => runtime.block_on(vc::verify_vc(&credential_json, contexts)),
        };
        if let Err(e) = &outcome {
            if let (Some(reason), false) = (
                e.downcast_ref::<vc::VcVerificationError>(),
                out_reason.is_null(),
            ) {
                write_c_string(out_reason, reason.code().to_string(), "out_reason")?;
            }
        }
        let result = map_anyhow(outcome)?;
        write_c_string(out_verify_result_json, result, "out_verify_result_json")?;
        write_bool(out_valid, true, "out_valid")?;
        Ok(())
    })
}
