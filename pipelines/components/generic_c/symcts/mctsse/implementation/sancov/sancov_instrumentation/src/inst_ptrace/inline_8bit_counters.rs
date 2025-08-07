use sancov_shared::sancov_ptrace_interface::*;

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
#[export_name = "__sanitizer_cov_8bit_counters_init"]
pub extern "C" fn __sanitizer_cov_8bit_counters_init(guards_start: *mut u8, guards_end: *mut u8) {
    unsafe {
        assert!(
            libc::syscall(
                SYSCALL_SANCOV_CAPTURE_INLINE_8BIT_COUNTERS,
                guards_start,
                guards_end
            ) == 0
        );
    }
}
