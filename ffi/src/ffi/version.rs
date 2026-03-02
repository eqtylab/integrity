use std::ffi::c_char;

use crate::ffi::{
    error::{run_ffi, IgStatus},
    util::write_c_string,
};

const ABI_VERSION_MAJOR: u32 = 0;
const ABI_VERSION_MINOR: u32 = 2;
const ABI_VERSION_PATCH: u32 = 0;

#[no_mangle]
pub extern "C" fn ig_abi_version_major() -> u32 {
    ABI_VERSION_MAJOR
}

#[no_mangle]
pub extern "C" fn ig_abi_version_minor() -> u32 {
    ABI_VERSION_MINOR
}

#[no_mangle]
pub extern "C" fn ig_abi_version_patch() -> u32 {
    ABI_VERSION_PATCH
}

#[no_mangle]
pub extern "C" fn ig_abi_version_string(
    out_version: *mut *mut c_char,
    err_out: *mut *mut c_char,
) -> IgStatus {
    run_ffi(err_out, || {
        write_c_string(
            out_version,
            format!(
                "{}.{}.{}",
                ABI_VERSION_MAJOR, ABI_VERSION_MINOR, ABI_VERSION_PATCH
            ),
            "out_version",
        )
    })
}

#[no_mangle]
pub extern "C" fn ig_core_crate_version(
    out_version: *mut *mut c_char,
    err_out: *mut *mut c_char,
) -> IgStatus {
    run_ffi(err_out, || {
        write_c_string(
            out_version,
            env!("CARGO_PKG_VERSION").to_string(),
            "out_version",
        )
    })
}
