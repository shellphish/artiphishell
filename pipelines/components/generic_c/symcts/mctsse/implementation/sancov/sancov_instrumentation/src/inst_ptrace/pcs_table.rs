use cty::c_void;
use sancov_shared::guest_data_structures::GuestPCTableEntry;
use sancov_shared::sancov_ptrace_interface::*;

use crate::util::find_elf_start;

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
#[export_name = "__sanitizer_cov_pcs_init"]
pub extern "C" fn __sanitizer_cov_pcs_init(
    pcs_start: *const GuestPCTableEntry,
    pcs_end: *const GuestPCTableEntry,
) {
    let module_start = find_elf_start(pcs_start as *const c_void);
    unsafe {
        assert!(
            libc::syscall(
                SYSCALL_SANCOV_CAPTURE_PC_TABLE,
                module_start,
                pcs_start,
                pcs_end
            ) == 0
        );
    }
}
