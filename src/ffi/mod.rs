use std::ffi::{c_char, CString};

mod blob_store;
mod dsse;
mod error;
mod intoto;
mod lineage_manifest;
mod lineage_statements;
mod model_signing;
mod runtime;
mod signer;
mod util;
mod vc;
mod version;

pub use blob_store::IgBlobStoreHandle;
pub use error::IgStatus;
pub use runtime::IgRuntimeHandle;
pub use signer::IgSignerHandle;

#[cfg(test)]
mod tests;

/// Owned byte buffer returned across the C ABI boundary.
///
/// Memory in `ptr` is allocated by this library and must be released with
/// [`ig_bytes_free`].
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IgBytes {
    /// Pointer to the first byte of the buffer, or null when empty.
    pub ptr: *mut u8,
    /// Number of valid bytes at `ptr`.
    pub len: usize,
}

/// # Safety
/// `s` must be a pointer returned by this library via `CString::into_raw`
/// and must not have been freed previously.
#[no_mangle]
pub unsafe extern "C" fn ig_string_free(s: *mut c_char) {
    if s.is_null() {
        return;
    }

    unsafe {
        drop(CString::from_raw(s));
    }
}

/// # Safety
/// `err` must be a pointer returned by this library via `CString::into_raw`
/// and must not have been freed previously.
#[no_mangle]
pub unsafe extern "C" fn ig_error_free(err: *mut c_char) {
    unsafe {
        ig_string_free(err);
    }
}

/// # Safety
/// `bytes.ptr` must point to a heap allocation created by this library, with
/// an allocation capacity equal to `bytes.len`, and must not be freed
/// previously.
#[no_mangle]
pub unsafe extern "C" fn ig_bytes_free(bytes: IgBytes) {
    if bytes.ptr.is_null() {
        return;
    }

    unsafe {
        drop(Vec::from_raw_parts(bytes.ptr, bytes.len, bytes.len));
    }
}
