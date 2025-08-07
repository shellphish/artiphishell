#[no_mangle]
#[export_name = "GLOBAL_8BIT_COUNTERS_START"]
static mut GLOBAL_8BIT_COUNTERS_START: *mut u8 = std::ptr::null_mut();

#[no_mangle]
#[export_name = "GLOBAL_8BIT_COUNTERS_END"]
static mut GLOBAL_8BIT_COUNTERS_END: *mut u8 = std::ptr::null_mut();

#[no_mangle]
#[export_name = "__sanitizer_cov_8bit_counters_init"]
pub extern "C" fn __sanitizer_cov_8bit_counters_init(guards_start: *mut u8, guards_end: *mut u8) {
    unsafe {
        assert!(GLOBAL_8BIT_COUNTERS_START.is_null() && GLOBAL_8BIT_COUNTERS_END.is_null());
        GLOBAL_8BIT_COUNTERS_START = guards_start;
        GLOBAL_8BIT_COUNTERS_END = guards_end;
    }
}
