use std::{ffi::c_char, path::PathBuf};

use crate::{
    ffi::{
        error::{map_anyhow, run_ffi, FfiError, IgStatus},
        runtime::IgRuntimeHandle,
        util::{
            as_ref, bytes_from_raw, cstr_to_string, optional_cstr_to_string, write_c_string,
            write_out_ptr,
        },
    },
    signer::{
        load_signer, save_signer, AkvConfig, AkvSigner, AuthServiceSigner, Ed25519Signer,
        P256Signer, Secp256k1Signer, SignerType, VCompNotarySigner, YubiHsmSigner,
    },
};

pub struct IgSignerHandle {
    pub(crate) signer: SignerType,
}

fn write_signer(
    out_signer: *mut *mut IgSignerHandle,
    out_did: *mut *mut c_char,
    signer: SignerType,
) -> Result<(), FfiError> {
    let did = signer.get_did_doc().id;
    write_out_ptr(out_signer, IgSignerHandle { signer }, "out_signer")?;
    write_c_string(out_did, did, "out_did")?;
    Ok(())
}

#[no_mangle]
pub extern "C" fn ig_signer_free(signer: *mut IgSignerHandle) {
    if signer.is_null() {
        return;
    }

    unsafe {
        drop(Box::from_raw(signer));
    }
}

#[no_mangle]
pub extern "C" fn ig_signer_get_did(
    signer: *const IgSignerHandle,
    out_did: *mut *mut c_char,
    err_out: *mut *mut c_char,
) -> IgStatus {
    run_ffi(err_out, || {
        let signer = as_ref(signer, "signer")?;
        let did = signer.signer.get_did_doc().id;
        write_c_string(out_did, did, "out_did")
    })
}

#[no_mangle]
pub extern "C" fn ig_signer_ed25519_create(
    out_signer: *mut *mut IgSignerHandle,
    out_did: *mut *mut c_char,
    err_out: *mut *mut c_char,
) -> IgStatus {
    run_ffi(err_out, || {
        let signer = map_anyhow(Ed25519Signer::create())?;
        write_signer(out_signer, out_did, SignerType::ED25519(signer))
    })
}

#[no_mangle]
pub extern "C" fn ig_signer_ed25519_import(
    secret_key_ptr: *const u8,
    secret_key_len: usize,
    out_signer: *mut *mut IgSignerHandle,
    out_did: *mut *mut c_char,
    err_out: *mut *mut c_char,
) -> IgStatus {
    run_ffi(err_out, || {
        if secret_key_len != 32 {
            return Err(FfiError::new(
                IgStatus::InvalidInput,
                format!("ed25519 secret key must be 32 bytes, got {secret_key_len}"),
            ));
        }

        let secret_key = bytes_from_raw(secret_key_ptr, secret_key_len, "secret_key_ptr")?;
        let signer = map_anyhow(Ed25519Signer::import(&secret_key))?;
        write_signer(out_signer, out_did, SignerType::ED25519(signer))
    })
}

#[no_mangle]
pub extern "C" fn ig_signer_p256_create(
    out_signer: *mut *mut IgSignerHandle,
    out_did: *mut *mut c_char,
    err_out: *mut *mut c_char,
) -> IgStatus {
    run_ffi(err_out, || {
        let signer = map_anyhow(P256Signer::create())?;
        write_signer(out_signer, out_did, SignerType::P256(signer))
    })
}

#[no_mangle]
pub extern "C" fn ig_signer_p256_import(
    secret_key_ptr: *const u8,
    secret_key_len: usize,
    out_signer: *mut *mut IgSignerHandle,
    out_did: *mut *mut c_char,
    err_out: *mut *mut c_char,
) -> IgStatus {
    run_ffi(err_out, || {
        if secret_key_len != 32 {
            return Err(FfiError::new(
                IgStatus::InvalidInput,
                format!("p256 secret key must be 32 bytes, got {secret_key_len}"),
            ));
        }

        let secret_key = bytes_from_raw(secret_key_ptr, secret_key_len, "secret_key_ptr")?;
        let signer = map_anyhow(P256Signer::import(&secret_key))?;
        write_signer(out_signer, out_did, SignerType::P256(signer))
    })
}

#[no_mangle]
pub extern "C" fn ig_signer_secp256k1_create(
    out_signer: *mut *mut IgSignerHandle,
    out_did: *mut *mut c_char,
    err_out: *mut *mut c_char,
) -> IgStatus {
    run_ffi(err_out, || {
        let signer = map_anyhow(Secp256k1Signer::create())?;
        write_signer(out_signer, out_did, SignerType::SECP256K1(signer))
    })
}

#[no_mangle]
pub extern "C" fn ig_signer_secp256k1_import(
    secret_key_ptr: *const u8,
    secret_key_len: usize,
    out_signer: *mut *mut IgSignerHandle,
    out_did: *mut *mut c_char,
    err_out: *mut *mut c_char,
) -> IgStatus {
    run_ffi(err_out, || {
        if secret_key_len != 32 {
            return Err(FfiError::new(
                IgStatus::InvalidInput,
                format!("secp256k1 secret key must be 32 bytes, got {secret_key_len}"),
            ));
        }

        let secret_key = bytes_from_raw(secret_key_ptr, secret_key_len, "secret_key_ptr")?;
        let signer = map_anyhow(Secp256k1Signer::import(&secret_key))?;
        write_signer(out_signer, out_did, SignerType::SECP256K1(signer))
    })
}

#[no_mangle]
pub extern "C" fn ig_signer_auth_service_create(
    runtime: *const IgRuntimeHandle,
    api_key: *const c_char,
    url: *const c_char,
    out_signer: *mut *mut IgSignerHandle,
    out_did: *mut *mut c_char,
    err_out: *mut *mut c_char,
) -> IgStatus {
    run_ffi(err_out, || {
        let runtime = as_ref(runtime, "runtime")?;
        let api_key = cstr_to_string(api_key, "api_key")?;
        let url = cstr_to_string(url, "url")?;

        let signer = map_anyhow(runtime.block_on(AuthServiceSigner::create(api_key, url)))?;
        write_signer(out_signer, out_did, SignerType::AuthService(signer))
    })
}

#[no_mangle]
pub extern "C" fn ig_signer_vcomp_notary_create(
    runtime: *const IgRuntimeHandle,
    url: *const c_char,
    pub_key_hex_or_null: *const c_char,
    out_signer: *mut *mut IgSignerHandle,
    out_did: *mut *mut c_char,
    err_out: *mut *mut c_char,
) -> IgStatus {
    run_ffi(err_out, || {
        let runtime = as_ref(runtime, "runtime")?;
        let url = cstr_to_string(url, "url")?;
        let pub_key = optional_cstr_to_string(pub_key_hex_or_null)?;

        let signer = map_anyhow(runtime.block_on(VCompNotarySigner::create(&url, pub_key)))?;
        write_signer(out_signer, out_did, SignerType::VCompNotarySigner(signer))
    })
}

#[no_mangle]
pub extern "C" fn ig_signer_akv_create(
    runtime: *const IgRuntimeHandle,
    config_json: *const c_char,
    key_name: *const c_char,
    out_signer: *mut *mut IgSignerHandle,
    out_did: *mut *mut c_char,
    err_out: *mut *mut c_char,
) -> IgStatus {
    run_ffi(err_out, || {
        let runtime = as_ref(runtime, "runtime")?;
        let config_json = cstr_to_string(config_json, "config_json")?;
        let key_name = cstr_to_string(key_name, "key_name")?;
        let config = serde_json::from_str::<AkvConfig>(&config_json).map_err(|e| {
            FfiError::new(
                IgStatus::JsonError,
                format!("failed to parse akv config json: {e}"),
            )
        })?;

        let signer = map_anyhow(runtime.block_on(AkvSigner::create(&config, key_name)))?;
        write_signer(out_signer, out_did, SignerType::AKV(signer))
    })
}

#[no_mangle]
pub extern "C" fn ig_signer_yubihsm_create(
    auth_key_id: u16,
    signing_key_id: u16,
    password: *const c_char,
    out_signer: *mut *mut IgSignerHandle,
    out_did: *mut *mut c_char,
    err_out: *mut *mut c_char,
) -> IgStatus {
    run_ffi(err_out, || {
        let password = cstr_to_string(password, "password")?;

        let signer = map_anyhow(YubiHsmSigner::create(auth_key_id, signing_key_id, password))?;
        write_signer(out_signer, out_did, SignerType::YubiHsm2Signer(signer))
    })
}

#[no_mangle]
pub extern "C" fn ig_signer_save(
    signer: *const IgSignerHandle,
    folder: *const c_char,
    name: *const c_char,
    err_out: *mut *mut c_char,
) -> IgStatus {
    run_ffi(err_out, || {
        let signer = as_ref(signer, "signer")?;
        let folder = cstr_to_string(folder, "folder")?;
        let name = cstr_to_string(name, "name")?;

        map_anyhow(save_signer(&signer.signer, PathBuf::from(folder), &name))?;
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn ig_signer_load(
    signer_file: *const c_char,
    out_signer: *mut *mut IgSignerHandle,
    out_did: *mut *mut c_char,
    err_out: *mut *mut c_char,
) -> IgStatus {
    run_ffi(err_out, || {
        let signer_file = cstr_to_string(signer_file, "signer_file")?;
        let signer = map_anyhow(load_signer(PathBuf::from(signer_file)))?;
        write_signer(out_signer, out_did, signer)
    })
}
