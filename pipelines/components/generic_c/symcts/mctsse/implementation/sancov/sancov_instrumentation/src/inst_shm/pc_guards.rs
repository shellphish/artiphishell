use sancov_shared::util::retaddr;

#[no_mangle]
#[export_name = "GLOBAL_PC_GUARDS_START"]
static mut GLOBAL_PC_GUARDS_START: *mut u32 = std::ptr::null_mut();

#[no_mangle]
#[export_name = "GLOBAL_PC_GUARDS_END"]
static mut GLOBAL_PC_GUARDS_END: *mut u32 = std::ptr::null_mut();

#[no_mangle]
#[export_name = "__sanitizer_cov_trace_pc_guard_init"]
pub extern "C" fn __sanitizer_cov_trace_pc_guard_init(
    guards_start: *mut u32,
    guards_end: *mut u32,
) {
    unsafe {
        assert!(GLOBAL_PC_GUARDS_START.is_null() && GLOBAL_PC_GUARDS_END.is_null());
        GLOBAL_PC_GUARDS_START = guards_start;
        GLOBAL_PC_GUARDS_END = guards_end;
    }
}

#[no_mangle]
#[export_name = "__sanitizer_cov_trace_pc_guard"]
pub extern "C" fn __sanitizer_cov_trace_pc_guard(guard_ptr: *mut u32) {
    let guard = unsafe {
        let p = guard_ptr
            .as_mut()
            .expect("Got a guard pointer that was not valid?");
        if *p == 0 {
            // let's deref it inside the unsafe block to make sure the reference is valid going forward
            return;
        }
        p
    };

    println!(
        "__sanitizer_cov_trace_pc_guard(guard={:?}={:?}), retaddr={:?}",
        guard_ptr,
        *guard,
        retaddr()
    );
    *guard += 1;
}
