use sancov_shared::sancov_pc_table_entry::PCTableEntry;

#[no_mangle]
#[export_name = "GLOBAL_PCS_START"]
static mut GLOBAL_PCS_START: *const PCTableEntry = std::ptr::null_mut();

#[no_mangle]
#[export_name = "GLOBAL_PCS_END"]
static mut GLOBAL_PCS_END: *const PCTableEntry = std::ptr::null_mut();

#[no_mangle]
#[export_name = "__sanitizer_cov_pcs_init"]
pub extern "C" fn __sanitizer_cov_pcs_init(
    pcs_start: *const PCTableEntry,
    pcs_end: *const PCTableEntry,
) {
    unsafe {
        assert!(GLOBAL_PCS_START.is_null() && GLOBAL_PCS_END.is_null());
        GLOBAL_PCS_START = pcs_start;
        GLOBAL_PCS_END = pcs_end;
    }
}
