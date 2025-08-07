use sancov_shared::sancov_ptrace_interface::*;

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
#[export_name = "__sanitizer_cov_bool_flag_init"]
pub extern "C" fn __sanitizer_cov_bool_flag_init(bools_start: *mut u8, bools_end: *mut u8) {
    unsafe {
        assert!(libc::syscall(SYSCALL_SANCOV_CAPTURE_INLINE_BOOLS, bools_start, bools_end) == 0);
    }
}
