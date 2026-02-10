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

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IgBytes {
    pub ptr: *mut u8,
    pub len: usize,
}

#[no_mangle]
pub extern "C" fn ig_string_free(s: *mut c_char) {
    if s.is_null() {
        return;
    }

    unsafe {
        drop(CString::from_raw(s));
    }
}

#[no_mangle]
pub extern "C" fn ig_error_free(err: *mut c_char) {
    ig_string_free(err);
}

#[no_mangle]
pub extern "C" fn ig_bytes_free(bytes: IgBytes) {
    if bytes.ptr.is_null() {
        return;
    }

    unsafe {
        drop(Vec::from_raw_parts(bytes.ptr, bytes.len, bytes.len));
    }
}
