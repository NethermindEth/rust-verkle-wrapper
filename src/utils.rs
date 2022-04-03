use std::ffi::CStr;
use std::mem::transmute;
use std::os::raw::c_char;
use tempfile::Builder;

pub fn assert_value(value1: *const u8, value2: [u8; 32]) {
    let _val: Box<[u8; 32]> = unsafe { transmute(value1) };
    let result = *_val;
    assert_eq!(result, value2);
}

pub fn get_boxed_value(value: [u8; 32]) -> *const u8 {
    unsafe { transmute(Box::new(value)) }
}

pub fn str_to_cstr(val: &str) -> *const c_char {
    let byte = val.as_bytes();
    unsafe { CStr::from_bytes_with_nul_unchecked(byte).as_ptr() }
}
