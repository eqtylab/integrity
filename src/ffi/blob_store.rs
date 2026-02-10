use std::{ffi::c_char, path::PathBuf, ptr, sync::Arc};

use crate::{
    blob_store::{AzureBlob, BlobStore, LocalFs, GCS, S3},
    ffi::{
        error::{map_anyhow, run_ffi, FfiError, IgStatus},
        runtime::IgRuntimeHandle,
        util::{
            as_mut, as_ref, bytes_from_raw, cstr_to_string, optional_cstr_to_string, write_bool,
            write_c_string, write_ig_bytes, write_out_ptr,
        },
        IgBytes,
    },
};

/// Opaque handle to a configured blob store instance for FFI consumers.
pub struct IgBlobStoreHandle {
    pub(crate) store: Arc<dyn BlobStore + Send + Sync>,
}

fn init_blob_store<S>(
    runtime: &IgRuntimeHandle,
    mut store: S,
) -> Result<IgBlobStoreHandle, FfiError>
where
    S: BlobStore + Send + Sync + 'static,
{
    map_anyhow(runtime.block_on(store.init()))?;
    Ok(IgBlobStoreHandle {
        store: Arc::new(store),
    })
}

#[no_mangle]
pub extern "C" fn ig_blob_store_free(store: *mut IgBlobStoreHandle) {
    if store.is_null() {
        return;
    }

    unsafe {
        drop(Box::from_raw(store));
    }
}

#[no_mangle]
pub extern "C" fn ig_blob_store_local_fs_new(
    runtime: *const IgRuntimeHandle,
    path: *const c_char,
    out_store: *mut *mut IgBlobStoreHandle,
    err_out: *mut *mut c_char,
) -> IgStatus {
    run_ffi(err_out, || {
        let runtime = as_ref(runtime, "runtime")?;
        let path = cstr_to_string(path, "path")?;

        let store = init_blob_store(runtime, LocalFs::new(PathBuf::from(path)))?;
        write_out_ptr(out_store, store, "out_store")
    })
}

#[no_mangle]
pub extern "C" fn ig_blob_store_s3_new(
    runtime: *const IgRuntimeHandle,
    region: *const c_char,
    bucket: *const c_char,
    folder: *const c_char,
    out_store: *mut *mut IgBlobStoreHandle,
    err_out: *mut *mut c_char,
) -> IgStatus {
    run_ffi(err_out, || {
        let runtime = as_ref(runtime, "runtime")?;
        let region = cstr_to_string(region, "region")?;
        let bucket = cstr_to_string(bucket, "bucket")?;
        let folder = cstr_to_string(folder, "folder")?;

        let store = init_blob_store(runtime, S3::new(region, bucket, folder))?;
        write_out_ptr(out_store, store, "out_store")
    })
}

#[no_mangle]
pub extern "C" fn ig_blob_store_gcs_new(
    runtime: *const IgRuntimeHandle,
    bucket: *const c_char,
    folder: *const c_char,
    out_store: *mut *mut IgBlobStoreHandle,
    err_out: *mut *mut c_char,
) -> IgStatus {
    run_ffi(err_out, || {
        let runtime = as_ref(runtime, "runtime")?;
        let bucket = cstr_to_string(bucket, "bucket")?;
        let folder = cstr_to_string(folder, "folder")?;

        let store = init_blob_store(runtime, GCS::new(bucket, folder))?;
        write_out_ptr(out_store, store, "out_store")
    })
}

#[no_mangle]
pub extern "C" fn ig_blob_store_azure_blob_new(
    runtime: *const IgRuntimeHandle,
    account: *const c_char,
    key: *const c_char,
    container: *const c_char,
    out_store: *mut *mut IgBlobStoreHandle,
    err_out: *mut *mut c_char,
) -> IgStatus {
    run_ffi(err_out, || {
        let runtime = as_ref(runtime, "runtime")?;
        let account = cstr_to_string(account, "account")?;
        let key = cstr_to_string(key, "key")?;
        let container = cstr_to_string(container, "container")?;

        let store = init_blob_store(runtime, AzureBlob::new(account, key, container))?;
        write_out_ptr(out_store, store, "out_store")
    })
}

#[no_mangle]
pub extern "C" fn ig_blob_store_exists(
    runtime: *const IgRuntimeHandle,
    store: *const IgBlobStoreHandle,
    cid: *const c_char,
    out_exists: *mut bool,
    err_out: *mut *mut c_char,
) -> IgStatus {
    run_ffi(err_out, || {
        let runtime = as_ref(runtime, "runtime")?;
        let store = as_ref(store, "store")?;
        let cid = cstr_to_string(cid, "cid")?;

        let exists = map_anyhow(runtime.block_on(store.store.exists(&cid)))?;
        write_bool(out_exists, exists, "out_exists")
    })
}

#[no_mangle]
pub extern "C" fn ig_blob_store_get(
    runtime: *const IgRuntimeHandle,
    store: *const IgBlobStoreHandle,
    cid: *const c_char,
    out_blob: *mut IgBytes,
    out_found: *mut bool,
    err_out: *mut *mut c_char,
) -> IgStatus {
    run_ffi(err_out, || {
        let runtime = as_ref(runtime, "runtime")?;
        let store = as_ref(store, "store")?;
        let cid = cstr_to_string(cid, "cid")?;

        let out_blob = as_mut(out_blob, "out_blob")?;
        *out_blob = IgBytes {
            ptr: ptr::null_mut(),
            len: 0,
        };

        let blob = map_anyhow(runtime.block_on(store.store.get(&cid)))?;
        match blob {
            Some(bytes) => {
                write_ig_bytes(out_blob, bytes, "out_blob")?;
                write_bool(out_found, true, "out_found")?;
            }
            None => {
                write_bool(out_found, false, "out_found")?;
            }
        }

        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn ig_blob_store_put(
    runtime: *const IgRuntimeHandle,
    store: *const IgBlobStoreHandle,
    blob_ptr: *const u8,
    blob_len: usize,
    multicodec_code: u64,
    expected_cid_or_null: *const c_char,
    out_cid: *mut *mut c_char,
    err_out: *mut *mut c_char,
) -> IgStatus {
    run_ffi(err_out, || {
        let runtime = as_ref(runtime, "runtime")?;
        let store = as_ref(store, "store")?;
        let blob = bytes_from_raw(blob_ptr, blob_len, "blob_ptr")?;
        let expected_cid = optional_cstr_to_string(expected_cid_or_null)?;

        let cid = map_anyhow(runtime.block_on(store.store.put(
            blob,
            multicodec_code,
            expected_cid.as_deref(),
        )))?;

        write_c_string(out_cid, cid, "out_cid")
    })
}
