use sancov_shared::util::retaddr;

#[no_mangle]
#[export_name = "__sanitizer_cov_trace_pc"]
pub extern "C" fn __sanitizer_cov_trace_pc() {
    println!("Traced PC @ {:?}", retaddr());
}
