use std::ffi::c_char;

use crate::ffi::{
    error::{run_ffi, IgStatus},
    util::write_out_ptr,
};

/// Opaque handle to the Tokio runtime used by asynchronous FFI operations.
pub struct IgRuntimeHandle {
    pub(crate) runtime: tokio::runtime::Runtime,
}

impl IgRuntimeHandle {
    pub(crate) fn block_on<F: std::future::Future>(&self, fut: F) -> F::Output {
        self.runtime.block_on(fut)
    }
}

#[no_mangle]
pub extern "C" fn ig_runtime_new(
    out_runtime: *mut *mut IgRuntimeHandle,
    err_out: *mut *mut c_char,
) -> IgStatus {
    run_ffi(err_out, || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| {
                crate::ffi::error::FfiError::new(
                    crate::ffi::error::IgStatus::RuntimeError,
                    format!("failed to initialize runtime: {e}"),
                )
            })?;
        write_out_ptr(out_runtime, IgRuntimeHandle { runtime }, "out_runtime")
    })
}

#[no_mangle]
pub extern "C" fn ig_runtime_free(runtime: *mut IgRuntimeHandle) {
    if runtime.is_null() {
        return;
    }

    unsafe {
        drop(Box::from_raw(runtime));
    }
}
