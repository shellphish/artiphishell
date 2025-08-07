use sancov_shared::{sancov_ptrace_interface::*, util::retaddr};

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
#[export_name = "__sanitizer_cov_trace_pc_guard"]
pub extern "C" fn __sanitizer_cov_trace_pc_guard(guard_ptr: *mut u32) {
    let callsite = retaddr();
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

    let new_val = unsafe {
        libc::syscall(
            SYSCALL_SANCOV_TRACE_PC_GUARD,
            guard_ptr,
            *guard_ptr,
            callsite,
        )
    };
    println!(
        "Instrumentation got back 0x{:x} from sancov ptrace syscall",
        new_val
    );
    // if let Some((mod_name, offset)) = get_module_and_offset(retaddr!()) {
    //     println!("Module: {}, offset: 0x{:x}", mod_name, offset);
    // }
    // println!("__sanitizer_cov_trace_pc_guard(guard={:?}={:?}), retaddr={:?}", guard_ptr, *guard, callsite);
    *guard = new_val as u32;
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
#[export_name = "__sanitizer_cov_trace_pc_guard_init"]
pub extern "C" fn __sanitizer_cov_trace_pc_guard_init(
    guards_start: *mut u32,
    guards_end: *mut u32,
) {
    unsafe {
        assert!(libc::syscall(SYSCALL_SANCOV_CAPTURE_PC_GUARDS, guards_start, guards_end) == 0);
    }
    // Done in the collector now!

    // let mut cur = guards_start;
    // while cur < guards_end {
    //     unsafe {
    //         *cur = 1;
    //         cur = cur.add(1);
    //     };
    // }
}
