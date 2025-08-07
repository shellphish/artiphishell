use cty::c_void;
use sancov_shared::util::retaddr;

#[no_mangle]
#[export_name = "__sanitizer_cov_trace_pc_indirect"]
pub extern "C" fn __sanitizer_cov_trace_pc_indirect(callee: *const c_void) {
    let callsite = retaddr();
    println!("Traced indirect edge from {:?} to {:?}", callsite, callee);
}
