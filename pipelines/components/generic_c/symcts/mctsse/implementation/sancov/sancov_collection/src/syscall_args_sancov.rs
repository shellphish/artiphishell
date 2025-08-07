use cty::c_void;
use pete::Tracee;
use sancov_shared::{
    guest_data_structures::{GuestPCTableEntry, GuestPointer},
    sancov_ptrace_interface::*,
};

use crate::syscall_args_generic::{SyscallArgsGeneric, SyscallArgsGenericExtractor};

type Result<T> = std::result::Result<T, pete::Error>;

#[derive(Debug, Eq, PartialEq)]
pub enum SancovSyscallArgs {
    TracePc {
        callsite: GuestPointer<*const c_void>,
    },
    TracePcGuard {
        guard: GuestPointer<*mut u32>,
        guard_val: usize,
        callsite: GuestPointer<*const c_void>,
    },
    CaptureInlineBoolsTable {
        start: GuestPointer<*mut u8>,
        end: GuestPointer<*mut u8>,
    },
    CaptureInline8BitCountersTable {
        start: GuestPointer<*mut u8>,
        end: GuestPointer<*mut u8>,
    },
    CapturePcGuardsTable {
        start: GuestPointer<*mut u32>,
        end: GuestPointer<*mut u32>,
    },
    CapturePcsTable {
        module_start: GuestPointer<*const c_void>,
        start: GuestPointer<*const GuestPCTableEntry>,
        end: GuestPointer<*const GuestPCTableEntry>,
    },
}

pub fn extract_sancov_syscall_args(tracee: &mut Tracee) -> Result<Option<SancovSyscallArgs>> {
    let regs = tracee.registers()?;
    let syscall_no = regs.orig_rax;
    // println!("syscall_no: {}", syscall_no);
    match syscall_no as i64 {
        SYSCALL_SANCOV_TRACE_PC => {
            let args = SyscallArgsGeneric::<1>::extract(tracee)?.args;
            Ok(Some(SancovSyscallArgs::TracePc {
                callsite: GuestPointer::<*const c_void>::new(args[0]),
            }))
        }
        SYSCALL_SANCOV_TRACE_PC_GUARD => {
            let args = SyscallArgsGeneric::<3>::extract(tracee)?.args;
            Ok(Some(SancovSyscallArgs::TracePcGuard {
                guard: GuestPointer::<*mut u32>::new(args[0]),
                guard_val: args[1] as usize,
                callsite: GuestPointer::<*const c_void>::new(args[2]),
            }))
        }
        SYSCALL_SANCOV_CAPTURE_PC_GUARDS => {
            let args = SyscallArgsGeneric::<2>::extract(tracee)?.args;
            Ok(Some(SancovSyscallArgs::CapturePcGuardsTable {
                start: args[0].into(),
                end: args[1].into(),
            }))
        }
        SYSCALL_SANCOV_CAPTURE_INLINE_8BIT_COUNTERS => {
            let args = SyscallArgsGeneric::<2>::extract(tracee)?.args;
            Ok(Some(SancovSyscallArgs::CaptureInline8BitCountersTable {
                start: args[0].into(),
                end: args[1].into(),
            }))
        }
        SYSCALL_SANCOV_CAPTURE_INLINE_BOOLS => {
            let args = SyscallArgsGeneric::<2>::extract(tracee)?.args;
            Ok(Some(SancovSyscallArgs::CaptureInlineBoolsTable {
                start: args[0].into(),
                end: args[1].into(),
            }))
        }
        SYSCALL_SANCOV_CAPTURE_PC_TABLE => {
            let args = SyscallArgsGeneric::<3>::extract(tracee)?.args;
            Ok(Some(SancovSyscallArgs::CapturePcsTable {
                module_start: args[0].into(),
                start: args[1].into(),
                end: args[2].into(),
            }))
        }
        _ => Ok(None),
    }
}
