use std::ffi::{c_char, CStr, CString};

use crate::ffi::{
    error::{FfiError, FfiResult, IgStatus},
    IgBytes,
};

pub(crate) fn as_ref<'a, T>(ptr: *const T, name: &str) -> FfiResult<&'a T> {
    if ptr.is_null() {
        return Err(FfiError::new(
            IgStatus::NullPointer,
            format!("{name} is a null pointer"),
        ));
    }

    Ok(unsafe { &*ptr })
}

pub(crate) fn as_mut<'a, T>(ptr: *mut T, name: &str) -> FfiResult<&'a mut T> {
    if ptr.is_null() {
        return Err(FfiError::new(
            IgStatus::NullPointer,
            format!("{name} is a null pointer"),
        ));
    }

    Ok(unsafe { &mut *ptr })
}

pub(crate) fn cstr_to_string(ptr: *const c_char, name: &str) -> FfiResult<String> {
    if ptr.is_null() {
        return Err(FfiError::new(
            IgStatus::NullPointer,
            format!("{name} is a null pointer"),
        ));
    }

    let s = unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .map_err(|e| FfiError::new(IgStatus::Utf8Error, format!("invalid utf-8 in {name}: {e}")))?
        .to_owned();

    Ok(s)
}

pub(crate) fn optional_cstr_to_string(ptr: *const c_char) -> FfiResult<Option<String>> {
    if ptr.is_null() {
        return Ok(None);
    }

    let s = unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .map_err(|e| FfiError::new(IgStatus::Utf8Error, format!("invalid utf-8: {e}")))?
        .to_owned();

    Ok(Some(s))
}

pub(crate) fn bytes_from_raw(ptr: *const u8, len: usize, name: &str) -> FfiResult<Vec<u8>> {
    if ptr.is_null() {
        return if len == 0 {
            Ok(Vec::new())
        } else {
            Err(FfiError::new(
                IgStatus::NullPointer,
                format!("{name} is a null pointer"),
            ))
        };
    }

    let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
    Ok(slice.to_vec())
}

pub(crate) fn write_c_string(out: *mut *mut c_char, value: String, name: &str) -> FfiResult<()> {
    if out.is_null() {
        return Err(FfiError::new(
            IgStatus::NullPointer,
            format!("{name} is a null pointer"),
        ));
    }

    let value = value.replace('\0', "\\0");
    let c_value = CString::new(value).map_err(|e| {
        FfiError::new(
            IgStatus::Utf8Error,
            format!("failed to encode {name} as C string: {e}"),
        )
    })?;

    unsafe {
        *out = c_value.into_raw();
    }

    Ok(())
}

pub(crate) fn write_out_ptr<T>(out: *mut *mut T, value: T, name: &str) -> FfiResult<()> {
    if out.is_null() {
        return Err(FfiError::new(
            IgStatus::NullPointer,
            format!("{name} is a null pointer"),
        ));
    }

    let boxed = Box::new(value);
    unsafe {
        *out = Box::into_raw(boxed);
    }

    Ok(())
}

pub(crate) fn write_bool(out: *mut bool, value: bool, name: &str) -> FfiResult<()> {
    if out.is_null() {
        return Err(FfiError::new(
            IgStatus::NullPointer,
            format!("{name} is a null pointer"),
        ));
    }

    unsafe {
        *out = value;
    }

    Ok(())
}

pub(crate) fn write_ig_bytes(out: *mut IgBytes, mut value: Vec<u8>, name: &str) -> FfiResult<()> {
    if out.is_null() {
        return Err(FfiError::new(
            IgStatus::NullPointer,
            format!("{name} is a null pointer"),
        ));
    }

    let bytes = IgBytes {
        ptr: value.as_mut_ptr(),
        len: value.len(),
    };
    std::mem::forget(value);

    unsafe {
        *out = bytes;
    }

    Ok(())
}
