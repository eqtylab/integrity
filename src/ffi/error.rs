use std::{
    ffi::{c_char, CString},
    panic::{catch_unwind, AssertUnwindSafe},
    ptr,
};

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Status codes returned by FFI entrypoints.
pub enum IgStatus {
    /// Operation completed successfully.
    Ok = 0,
    /// Input value failed validation.
    InvalidInput = 1,
    /// Required pointer input was null.
    NullPointer = 2,
    /// UTF-8 or string encoding/decoding error.
    Utf8Error = 3,
    /// JSON parsing or serialization error.
    JsonError = 4,
    /// Signature or proof verification failed.
    VerificationFailed = 5,
    /// Requested operation is not supported in the current build/runtime.
    NotSupported = 6,
    /// Runtime subsystem initialization or execution error.
    RuntimeError = 7,
    /// Unexpected internal failure.
    InternalError = 255,
}

pub(crate) type FfiResult<T> = Result<T, FfiError>;

#[derive(Debug)]
pub(crate) struct FfiError {
    pub(crate) status: IgStatus,
    pub(crate) message: String,
}

impl FfiError {
    pub(crate) fn new(status: IgStatus, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    pub(crate) fn from_anyhow(err: anyhow::Error) -> Self {
        let status = classify_anyhow(&err);
        Self {
            status,
            message: err.to_string(),
        }
    }
}

fn classify_anyhow(err: &anyhow::Error) -> IgStatus {
    if err.downcast_ref::<serde_json::Error>().is_some() {
        return IgStatus::JsonError;
    }

    if err.downcast_ref::<std::str::Utf8Error>().is_some()
        || err.downcast_ref::<std::string::FromUtf8Error>().is_some()
        || err.downcast_ref::<std::ffi::NulError>().is_some()
    {
        return IgStatus::Utf8Error;
    }

    let msg = err.to_string().to_ascii_lowercase();
    if msg.contains("null pointer") {
        IgStatus::NullPointer
    } else if msg.contains("verification failed") || msg.contains("invalid signature") {
        IgStatus::VerificationFailed
    } else if msg.contains("not implemented") || msg.contains("unsupported") {
        IgStatus::NotSupported
    } else if msg.contains("invalid") || msg.contains("missing") || msg.contains("expected") {
        IgStatus::InvalidInput
    } else {
        IgStatus::InternalError
    }
}

pub(crate) fn map_anyhow<T>(res: anyhow::Result<T>) -> FfiResult<T> {
    res.map_err(FfiError::from_anyhow)
}

pub(crate) fn clear_error(err_out: *mut *mut c_char) {
    if err_out.is_null() {
        return;
    }

    unsafe {
        *err_out = ptr::null_mut();
    }
}

pub(crate) fn set_error(err_out: *mut *mut c_char, message: impl Into<String>) {
    if err_out.is_null() {
        return;
    }

    let msg = sanitize_error_message(message.into());
    let c_message = CString::new(msg).unwrap_or_else(|_| {
        CString::new("failed to encode error message").expect("static message is valid")
    });

    unsafe {
        *err_out = c_message.into_raw();
    }
}

fn sanitize_error_message(message: String) -> String {
    message.replace('\0', "\\0")
}

pub(crate) fn run_ffi<F>(err_out: *mut *mut c_char, f: F) -> IgStatus
where
    F: FnOnce() -> FfiResult<()>,
{
    clear_error(err_out);

    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(())) => IgStatus::Ok,
        Ok(Err(err)) => {
            set_error(err_out, err.message);
            err.status
        }
        Err(_) => {
            set_error(err_out, "panic in FFI function");
            IgStatus::InternalError
        }
    }
}
