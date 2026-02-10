use std::{
    ffi::{c_char, CStr, CString},
    ptr,
};

use serde_json::Value;

use super::{
    blob_store, dsse, error::IgStatus, intoto, lineage_statements, model_signing, runtime, signer,
    vc, IgBytes,
};

fn cstring(s: &str) -> CString {
    CString::new(s).expect("test string has no NUL")
}

fn take_owned_c_string(ptr: *mut c_char) -> String {
    assert!(!ptr.is_null(), "expected non-null C string pointer");
    let s = unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .expect("valid utf-8")
        .to_owned();
    super::ig_string_free(ptr);
    s
}

fn assert_ok(status: IgStatus, err: *mut c_char) {
    if status == IgStatus::Ok {
        assert!(err.is_null(), "expected null err_out on success");
        return;
    }

    let err_msg = if err.is_null() {
        String::from("<no error message>")
    } else {
        let s = unsafe { CStr::from_ptr(err) }
            .to_str()
            .expect("valid utf-8")
            .to_owned();
        super::ig_error_free(err);
        s
    };

    panic!("expected IgStatus::Ok, got {:?}: {}", status, err_msg);
}

#[test]
fn ffi_runtime_signer_dsse_smoke() {
    let mut runtime_handle = ptr::null_mut();
    let mut err_out = ptr::null_mut();
    let status = runtime::ig_runtime_new(&mut runtime_handle, &mut err_out);
    assert_ok(status, err_out);

    let mut signer_handle = ptr::null_mut();
    let mut signer_did = ptr::null_mut();
    let status =
        signer::ig_signer_ed25519_create(&mut signer_handle, &mut signer_did, &mut err_out);
    assert_ok(status, err_out);
    let signer_did = take_owned_c_string(signer_did);
    assert!(signer_did.starts_with("did:key:"));

    let payload = b"hello ffi";
    let payload_type = cstring("application/vnd.in-toto+json");
    let mut envelope_json_ptr = ptr::null_mut();
    let status = dsse::ig_dsse_sign(
        runtime_handle,
        signer_handle,
        payload.as_ptr(),
        payload.len(),
        payload_type.as_ptr(),
        &mut envelope_json_ptr,
        &mut err_out,
    );
    assert_ok(status, err_out);

    let envelope_json = take_owned_c_string(envelope_json_ptr);
    let envelope: Value = serde_json::from_str(&envelope_json).expect("valid json envelope");
    assert_eq!(
        envelope["payloadType"],
        Value::String(String::from("application/vnd.in-toto+json"))
    );
    assert!(
        envelope["signatures"]
            .as_array()
            .unwrap_or(&Vec::new())
            .len()
            == 1
    );

    signer::ig_signer_free(signer_handle);
    runtime::ig_runtime_free(runtime_handle);
}

#[test]
fn ffi_vc_issue_and_verify_smoke() {
    let mut runtime_handle = ptr::null_mut();
    let mut err_out = ptr::null_mut();
    let status = runtime::ig_runtime_new(&mut runtime_handle, &mut err_out);
    assert_ok(status, err_out);

    let mut signer_handle = ptr::null_mut();
    let mut signer_did = ptr::null_mut();
    let status =
        signer::ig_signer_ed25519_create(&mut signer_handle, &mut signer_did, &mut err_out);
    assert_ok(status, err_out);
    super::ig_string_free(signer_did);

    let subject = cstring("did:key:z6MksNPQf5wQwQfA2a5JY9xY8h6CZ9nHp4Y5qpc4kTYqN6xw");
    let mut vc_json_ptr = ptr::null_mut();
    let status = vc::ig_vc_issue(
        runtime_handle,
        signer_handle,
        subject.as_ptr(),
        &mut vc_json_ptr,
        &mut err_out,
    );
    assert_ok(status, err_out);

    let vc_json = take_owned_c_string(vc_json_ptr);
    let issued_vc: Value = serde_json::from_str(&vc_json).expect("valid issued vc json");
    assert!(issued_vc.get("proof").is_some());

    let vc_json_c = cstring(&vc_json);
    let mut verify_result_ptr = ptr::null_mut();
    let mut is_valid = false;
    let status = vc::ig_vc_verify(
        runtime_handle,
        vc_json_c.as_ptr(),
        &mut verify_result_ptr,
        &mut is_valid,
        &mut err_out,
    );
    assert_ok(status, err_out);

    let verify_result = take_owned_c_string(verify_result_ptr);
    assert!(verify_result.contains("VC verification result"));
    assert!(is_valid);

    signer::ig_signer_free(signer_handle);
    runtime::ig_runtime_free(runtime_handle);
}

#[test]
fn ffi_blob_store_local_fs_roundtrip() {
    let mut runtime_handle = ptr::null_mut();
    let mut err_out = ptr::null_mut();
    let status = runtime::ig_runtime_new(&mut runtime_handle, &mut err_out);
    assert_ok(status, err_out);

    let tmp_dir = std::env::temp_dir().join(format!("integrity-ffi-test-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&tmp_dir).expect("create temp dir");
    let path = cstring(tmp_dir.to_string_lossy().as_ref());

    let mut store_handle = ptr::null_mut();
    let status = blob_store::ig_blob_store_local_fs_new(
        runtime_handle,
        path.as_ptr(),
        &mut store_handle,
        &mut err_out,
    );
    assert_ok(status, err_out);

    let blob = b"ffi blob";
    let mut cid_ptr = ptr::null_mut();
    let status = blob_store::ig_blob_store_put(
        runtime_handle,
        store_handle,
        blob.as_ptr(),
        blob.len(),
        0x55,
        ptr::null(),
        &mut cid_ptr,
        &mut err_out,
    );
    assert_ok(status, err_out);

    let cid = take_owned_c_string(cid_ptr);
    assert!(!cid.is_empty());
    let cid_c = cstring(&cid);

    let mut exists = false;
    let status = blob_store::ig_blob_store_exists(
        runtime_handle,
        store_handle,
        cid_c.as_ptr(),
        &mut exists,
        &mut err_out,
    );
    assert_ok(status, err_out);
    assert!(exists);

    let mut out_blob = IgBytes::default();
    let mut found = false;
    let status = blob_store::ig_blob_store_get(
        runtime_handle,
        store_handle,
        cid_c.as_ptr(),
        &mut out_blob,
        &mut found,
        &mut err_out,
    );
    assert_ok(status, err_out);
    assert!(found);

    let roundtrip = unsafe { std::slice::from_raw_parts(out_blob.ptr, out_blob.len) };
    assert_eq!(roundtrip, blob);
    super::ig_bytes_free(out_blob);

    blob_store::ig_blob_store_free(store_handle);
    runtime::ig_runtime_free(runtime_handle);
    let _ = std::fs::remove_dir_all(tmp_dir);
}

#[test]
fn ffi_model_signing_and_intoto_digest_smoke() {
    let mut runtime_handle = ptr::null_mut();
    let mut err_out = ptr::null_mut();
    let status = runtime::ig_runtime_new(&mut runtime_handle, &mut err_out);
    assert_ok(status, err_out);

    let model_name = cstring("demo-model");
    let mut hashes = std::collections::HashMap::new();
    hashes.insert(String::from("weights.bin"), hex::encode([7_u8; 32]));
    let hashes_json = cstring(&serde_json::to_string(&hashes).unwrap());

    let mut statement_json_ptr = ptr::null_mut();
    let status = model_signing::ig_model_signing_create_intoto_statement_from_hashes(
        runtime_handle,
        model_name.as_ptr(),
        hashes_json.as_ptr(),
        false,
        ptr::null(),
        &mut statement_json_ptr,
        &mut err_out,
    );
    assert_ok(status, err_out);

    let statement_json = take_owned_c_string(statement_json_ptr);
    let statement: Value = serde_json::from_str(&statement_json).expect("valid statement json");
    assert!(statement.get("predicate").is_some());

    let cid = cstring("bafkr4icb7a4uceploe5cefs4i3eqvohq7wjztsjafd6w2kejiszd75n7oy");
    let mut digest_json_ptr = ptr::null_mut();
    let status =
        intoto::ig_intoto_digest_from_cid(cid.as_ptr(), &mut digest_json_ptr, &mut err_out);
    assert_ok(status, err_out);

    let digest_json = take_owned_c_string(digest_json_ptr);
    let digest_map: std::collections::HashMap<String, String> =
        serde_json::from_str(&digest_json).expect("valid digest json");
    assert_eq!(
        digest_map.get("cid").map(String::as_str),
        Some(cid.to_str().unwrap())
    );

    runtime::ig_runtime_free(runtime_handle);
}

#[test]
fn ffi_lineage_statement_create_and_utils_smoke() {
    let mut runtime_handle = ptr::null_mut();
    let mut err_out = ptr::null_mut();
    let status = runtime::ig_runtime_new(&mut runtime_handle, &mut err_out);
    assert_ok(status, err_out);

    let request = serde_json::json!({
        "subject": "bafkr4ibthuzk3zug7ghmx63yjqaiu6rx4hhfdv3453j5bodskgw57bx2ya",
        "association": "baga6yaq6echz7kjzuhzubnsq2mqkw5oxpkrio5nwb4fibzkwaqke3hqbc25g4",
        "registeredBy": "did:key:z6Mkw2PvzC9DHXiYQHMDRwyxCCV9n4EDc6vqqp1uyi9nrwsP",
        "timestamp": "2025-01-01T00:00:00Z"
    });
    let request_c = cstring(&request.to_string());

    let mut statement_ptr = ptr::null_mut();
    let status = lineage_statements::ig_lineage_statement_create_association(
        runtime_handle,
        request_c.as_ptr(),
        &mut statement_ptr,
        &mut err_out,
    );
    assert_ok(status, err_out);

    let statement_json = take_owned_c_string(statement_ptr);
    let statement: Value = serde_json::from_str(&statement_json).expect("valid statement json");
    let statement_type = statement
        .get("@type")
        .and_then(Value::as_str)
        .expect("statement type");
    assert_eq!(statement_type, "AssociationRegistration");
    let statement_id = statement
        .get("@id")
        .and_then(Value::as_str)
        .expect("statement id");

    let statement_json_c = cstring(&statement_json);

    let mut cid_ptr = ptr::null_mut();
    let status = lineage_statements::ig_lineage_statement_compute_cid(
        runtime_handle,
        statement_json_c.as_ptr(),
        &mut cid_ptr,
        &mut err_out,
    );
    assert_ok(status, err_out);
    let computed_id = take_owned_c_string(cid_ptr);
    assert_eq!(computed_id, statement_id);

    let mut extracted_id_ptr = ptr::null_mut();
    let status = lineage_statements::ig_lineage_statement_extract_id(
        statement_json_c.as_ptr(),
        &mut extracted_id_ptr,
        &mut err_out,
    );
    assert_ok(status, err_out);
    let extracted_id = take_owned_c_string(extracted_id_ptr);
    assert_eq!(extracted_id, statement_id);

    let mut extracted_type_ptr = ptr::null_mut();
    let status = lineage_statements::ig_lineage_statement_extract_type(
        statement_json_c.as_ptr(),
        &mut extracted_type_ptr,
        &mut err_out,
    );
    assert_ok(status, err_out);
    let extracted_type = take_owned_c_string(extracted_type_ptr);
    assert_eq!(extracted_type, "AssociationRegistration");

    let mut filename_ptr = ptr::null_mut();
    let status = lineage_statements::ig_lineage_statement_jsonld_filename(
        statement_json_c.as_ptr(),
        &mut filename_ptr,
        &mut err_out,
    );
    assert_ok(status, err_out);
    let filename = take_owned_c_string(filename_ptr);
    assert!(filename.ends_with(".jsonld"));

    let mut refs_ptr = ptr::null_mut();
    let status = lineage_statements::ig_lineage_statement_referenced_cids_json(
        statement_json_c.as_ptr(),
        &mut refs_ptr,
        &mut err_out,
    );
    assert_ok(status, err_out);
    let refs_json = take_owned_c_string(refs_ptr);
    let refs: Vec<String> = serde_json::from_str(&refs_json).expect("valid refs");
    assert_eq!(refs.len(), 2);

    let mut registered_by_ptr = ptr::null_mut();
    let status = lineage_statements::ig_lineage_statement_registered_by(
        statement_json_c.as_ptr(),
        &mut registered_by_ptr,
        &mut err_out,
    );
    assert_ok(status, err_out);
    let registered_by = take_owned_c_string(registered_by_ptr);
    assert_eq!(
        registered_by,
        "did:key:z6Mkw2PvzC9DHXiYQHMDRwyxCCV9n4EDc6vqqp1uyi9nrwsP"
    );

    runtime::ig_runtime_free(runtime_handle);
}

#[test]
fn ffi_lineage_statement_create_did_regular_smoke() {
    let mut runtime_handle = ptr::null_mut();
    let mut err_out = ptr::null_mut();
    let status = runtime::ig_runtime_new(&mut runtime_handle, &mut err_out);
    assert_ok(status, err_out);

    let request = serde_json::json!({
        "did": "did:key:z6Mkw2PvzC9DHXiYQHMDRwyxCCV9n4EDc6vqqp1uyi9nrwsP",
        "registeredBy": "did:key:z6Mkw2PvzC9DHXiYQHMDRwyxCCV9n4EDc6vqqp1uyi9nrwsP",
        "timestamp": "2025-01-01T00:00:00Z"
    });
    let request_c = cstring(&request.to_string());

    let mut statement_ptr = ptr::null_mut();
    let status = lineage_statements::ig_lineage_statement_create_did_regular(
        runtime_handle,
        request_c.as_ptr(),
        &mut statement_ptr,
        &mut err_out,
    );
    assert_ok(status, err_out);

    let statement_json = take_owned_c_string(statement_ptr);
    let statement: Value = serde_json::from_str(&statement_json).expect("valid statement json");
    let statement_type = statement
        .get("@type")
        .and_then(Value::as_str)
        .expect("statement type");
    assert_eq!(statement_type, "DidRegistration");

    runtime::ig_runtime_free(runtime_handle);
}

#[test]
fn ffi_versions_smoke() {
    assert_eq!(super::version::ig_abi_version_major(), 0);
    assert_eq!(super::version::ig_abi_version_minor(), 2);

    let mut err_out = ptr::null_mut();
    let mut version_ptr = ptr::null_mut();
    let status = super::version::ig_abi_version_string(&mut version_ptr, &mut err_out);
    assert_ok(status, err_out);

    let version = take_owned_c_string(version_ptr);
    assert_eq!(version, "0.2.0");
}
