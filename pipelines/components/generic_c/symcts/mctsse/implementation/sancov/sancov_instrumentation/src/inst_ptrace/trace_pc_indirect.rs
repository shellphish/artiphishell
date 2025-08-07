use cty::c_void;
use sancov_shared::{sancov_ptrace_interface::*, util::retaddr};

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
#[export_name = "__sanitizer_cov_trace_pc_indirect"]
pub extern "C" fn __sanitizer_cov_trace_pc_indirect(callee: *const c_void) {
    let callsite = retaddr();
    unsafe {
        assert!(libc::syscall(SYSCALL_SANCOV_TRACE_PC_INDIRECT, callsite, callee) == 0);
    };
}
