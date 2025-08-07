#[no_mangle]
#[export_name = "GLOBAL_BOOL_FLAGS_START"]
static mut GLOBAL_BOOL_FLAGS_START: *mut u8 = std::ptr::null_mut();

#[no_mangle]
#[export_name = "GLOBAL_BOOL_FLAGS_END"]
static mut GLOBAL_BOOL_FLAGS_END: *mut u8 = std::ptr::null_mut();

#[no_mangle]
#[export_name = "__sanitizer_cov_bool_flag_init"]
pub extern "C" fn __sanitizer_cov_bool_flag_init(bools_start: *mut u8, bools_end: *mut u8) {
    unsafe {
        assert!(GLOBAL_BOOL_FLAGS_START.is_null() && GLOBAL_BOOL_FLAGS_END.is_null());
        GLOBAL_BOOL_FLAGS_START = bools_start;
        GLOBAL_BOOL_FLAGS_END = bools_end;
    }
}
