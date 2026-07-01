use std::{
    ffi::{c_char, CString},
    path::PathBuf,
    ptr,
    sync::Arc,
};

#[cfg(feature = "blob-azure")]
use crate::blob_store::AzureBlob;
#[cfg(feature = "blob-local")]
use crate::blob_store::LocalFs;
#[cfg(feature = "blob-gcs")]
use crate::blob_store::GCS;
#[cfg(feature = "blob-s3")]
use crate::blob_store::S3;
use crate::{
    blob_store::{BlobPut, BlobStore},
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

#[repr(C)]
pub struct IgBlobPutRequest {
    pub blob_ptr: *const u8,
    pub blob_len: usize,
    pub multicodec_code: u64,
    pub expected_cid_or_null: *const c_char,
}

#[repr(C)]
pub struct IgBlobPutResult {
    pub cid: *mut c_char,
}

#[repr(C)]
pub struct IgBlobGetResult {
    pub cid: *mut c_char,
    pub blob: IgBytes,
    pub found: bool,
}

#[repr(C)]
pub struct IgBlobExistsResult {
    pub cid: *mut c_char,
    pub exists: bool,
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
#[cfg(feature = "blob-local")]
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
#[cfg(feature = "blob-s3")]
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
#[cfg(feature = "blob-gcs")]
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
#[cfg(feature = "blob-azure")]
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

#[no_mangle]
pub extern "C" fn ig_blob_store_exists_many(
    runtime: *const IgRuntimeHandle,
    store: *const IgBlobStoreHandle,
    cids: *const *const c_char,
    cids_len: usize,
    out_results: *mut *mut IgBlobExistsResult,
    out_results_len: *mut usize,
    err_out: *mut *mut c_char,
) -> IgStatus {
    run_ffi(err_out, || {
        let runtime = as_ref(runtime, "runtime")?;
        let store = as_ref(store, "store")?;
        let cids = c_string_slice(cids, cids_len, "cids")?;
        validate_result_array_out(out_results, out_results_len, "out_results")?;

        let results = map_anyhow(runtime.block_on(store.store.exists_many(cids)))?
            .into_iter()
            .map(|result| {
                Ok(IgBlobExistsResult {
                    cid: c_string_ptr(result.cid, "cid")?,
                    exists: result.exists,
                })
            })
            .collect::<Result<Vec<_>, FfiError>>()?;

        write_result_array(out_results, out_results_len, results, "out_results")
    })
}

#[no_mangle]
pub extern "C" fn ig_blob_store_get_many(
    runtime: *const IgRuntimeHandle,
    store: *const IgBlobStoreHandle,
    cids: *const *const c_char,
    cids_len: usize,
    out_results: *mut *mut IgBlobGetResult,
    out_results_len: *mut usize,
    err_out: *mut *mut c_char,
) -> IgStatus {
    run_ffi(err_out, || {
        let runtime = as_ref(runtime, "runtime")?;
        let store = as_ref(store, "store")?;
        let cids = c_string_slice(cids, cids_len, "cids")?;
        validate_result_array_out(out_results, out_results_len, "out_results")?;

        let results = map_anyhow(runtime.block_on(store.store.get_many(cids)))?
            .into_iter()
            .map(|result| {
                let mut blob = IgBytes::default();
                let found = if let Some(bytes) = result.blob {
                    write_ig_bytes(&mut blob, bytes, "blob")?;
                    true
                } else {
                    false
                };

                Ok(IgBlobGetResult {
                    cid: c_string_ptr(result.cid, "cid")?,
                    blob,
                    found,
                })
            })
            .collect::<Result<Vec<_>, FfiError>>()?;

        write_result_array(out_results, out_results_len, results, "out_results")
    })
}

#[no_mangle]
pub extern "C" fn ig_blob_store_put_many(
    runtime: *const IgRuntimeHandle,
    store: *const IgBlobStoreHandle,
    blobs: *const IgBlobPutRequest,
    blobs_len: usize,
    out_results: *mut *mut IgBlobPutResult,
    out_results_len: *mut usize,
    err_out: *mut *mut c_char,
) -> IgStatus {
    run_ffi(err_out, || {
        let runtime = as_ref(runtime, "runtime")?;
        let store = as_ref(store, "store")?;
        let blobs = blob_put_slice(blobs, blobs_len, "blobs")?;
        validate_result_array_out(out_results, out_results_len, "out_results")?;

        let results = map_anyhow(runtime.block_on(store.store.put_many(blobs)))?
            .into_iter()
            .map(|result| {
                Ok(IgBlobPutResult {
                    cid: c_string_ptr(result.cid, "cid")?,
                })
            })
            .collect::<Result<Vec<_>, FfiError>>()?;

        write_result_array(out_results, out_results_len, results, "out_results")
    })
}

#[no_mangle]
pub unsafe extern "C" fn ig_blob_store_exists_results_free(
    results: *mut IgBlobExistsResult,
    results_len: usize,
) {
    if results.is_null() {
        return;
    }

    let results =
        unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(results, results_len)) };
    for result in results.into_vec() {
        free_c_string(result.cid);
    }
}

#[no_mangle]
pub unsafe extern "C" fn ig_blob_store_get_results_free(
    results: *mut IgBlobGetResult,
    results_len: usize,
) {
    if results.is_null() {
        return;
    }

    let results =
        unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(results, results_len)) };
    for result in results.into_vec() {
        free_c_string(result.cid);
        free_ig_bytes(result.blob);
    }
}

#[no_mangle]
pub unsafe extern "C" fn ig_blob_store_put_results_free(
    results: *mut IgBlobPutResult,
    results_len: usize,
) {
    if results.is_null() {
        return;
    }

    let results =
        unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(results, results_len)) };
    for result in results.into_vec() {
        free_c_string(result.cid);
    }
}

fn c_string_slice(
    ptr: *const *const c_char,
    len: usize,
    name: &str,
) -> Result<Vec<String>, FfiError> {
    if ptr.is_null() {
        if len == 0 {
            return Ok(Vec::new());
        }

        return Err(FfiError::new(
            IgStatus::NullPointer,
            format!("{name} is a null pointer"),
        ));
    }

    unsafe { std::slice::from_raw_parts(ptr, len) }
        .iter()
        .enumerate()
        .map(|(index, cid)| cstr_to_string(*cid, &format!("{name}[{index}]")))
        .collect()
}

fn blob_put_slice(
    ptr: *const IgBlobPutRequest,
    len: usize,
    name: &str,
) -> Result<Vec<BlobPut>, FfiError> {
    if ptr.is_null() {
        if len == 0 {
            return Ok(Vec::new());
        }

        return Err(FfiError::new(
            IgStatus::NullPointer,
            format!("{name} is a null pointer"),
        ));
    }

    unsafe { std::slice::from_raw_parts(ptr, len) }
        .iter()
        .enumerate()
        .map(|(index, request)| {
            Ok(BlobPut {
                blob: bytes_from_raw(
                    request.blob_ptr,
                    request.blob_len,
                    &format!("{name}[{index}].blob_ptr"),
                )?,
                multicodec_code: request.multicodec_code,
                cid: optional_cstr_to_string(request.expected_cid_or_null)?,
            })
        })
        .collect()
}

fn c_string_ptr(value: String, name: &str) -> Result<*mut c_char, FfiError> {
    let value = value.replace('\0', "\\0");
    let c_value = CString::new(value).map_err(|e| {
        FfiError::new(
            IgStatus::Utf8Error,
            format!("failed to encode {name} as C string: {e}"),
        )
    })?;

    Ok(c_value.into_raw())
}

fn validate_result_array_out<T>(
    out_results: *mut *mut T,
    out_results_len: *mut usize,
    name: &str,
) -> Result<(), FfiError> {
    if out_results.is_null() {
        return Err(FfiError::new(
            IgStatus::NullPointer,
            format!("{name} is a null pointer"),
        ));
    }
    if out_results_len.is_null() {
        return Err(FfiError::new(
            IgStatus::NullPointer,
            format!("{name}_len is a null pointer"),
        ));
    }

    Ok(())
}

fn write_result_array<T>(
    out_results: *mut *mut T,
    out_results_len: *mut usize,
    results: Vec<T>,
    name: &str,
) -> Result<(), FfiError> {
    validate_result_array_out(out_results, out_results_len, name)?;

    if results.is_empty() {
        unsafe {
            *out_results = ptr::null_mut();
            *out_results_len = 0;
        }

        return Ok(());
    }

    let mut results = results.into_boxed_slice();
    let len = results.len();
    let ptr = results.as_mut_ptr();
    std::mem::forget(results);

    unsafe {
        *out_results = ptr;
        *out_results_len = len;
    }

    Ok(())
}

fn free_c_string(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }

    unsafe {
        drop(CString::from_raw(ptr));
    }
}

fn free_ig_bytes(bytes: IgBytes) {
    if bytes.ptr.is_null() {
        return;
    }

    unsafe {
        drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(
            bytes.ptr, bytes.len,
        )));
    }
}
