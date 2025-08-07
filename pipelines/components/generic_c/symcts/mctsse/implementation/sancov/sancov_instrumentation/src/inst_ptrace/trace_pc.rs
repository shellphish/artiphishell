use sancov_shared::{sancov_ptrace_interface::*, util::retaddr};

#[no_mangle]
#[export_name = "__sanitizer_cov_trace_pc"]
pub extern "C" fn __sanitizer_cov_trace_pc() {
    unsafe {
        assert!(libc::syscall(SYSCALL_SANCOV_TRACE_PC, retaddr()) == 0);
    }
}
