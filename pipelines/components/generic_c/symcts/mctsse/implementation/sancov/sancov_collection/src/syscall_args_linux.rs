#[derive(Debug, Eq, PartialEq)]
enum SyscallArgs {
    Read { fd: i32, buf: Pointer, size: size_t},
    Write { fd: i32, buf: Pointer, size: size_t, data: EncodedString},
    Mprotect { addr: Pointer, len: Size_T, prot: Size_T},
    Munmap { addr: Pointer, len: Size_T },
    Generic {}
}

fn extract_linux_syscall_args(tracee: &mut Tracee) -> Result<SyscallArgs> {
    let regs = tracee.registers()?;
    let syscall_no = regs.orig_rax;
    match syscall_no as i64 {
        syscall_numbers::native::SYS_read => {
            let args = SyscallArgsGeneric::<3>::extract(tracee)?.args;
            Ok(SyscallArgs::Read { fd: args[0] as i32, buf: Pointer(args[1]), size: args[2] as size_t})
        },
        syscall_numbers::native::SYS_write => {
            let args = SyscallArgsGeneric::<3>::extract(tracee)?.args;
            Ok(SyscallArgs::Write {
                fd: args[0] as i32,
                buf: Pointer(args[1]),
                size: args[2] as size_t,
                data: EncodedString(tracee.read_memory(args[1] as u64, args[2])?)
            })
        }
        syscall_numbers::native::SYS_munmap => {
            let args = SyscallArgsGeneric::<2>::extract(tracee)?.args;
            Ok(SyscallArgs::Munmap {
                addr: Pointer(args[0]),
                len: Size_T(args[1] as size_t),
            })
        }
        syscall_numbers::native::SYS_mprotect => {
            let args = SyscallArgsGeneric::<3>::extract(tracee)?.args;
            Ok(SyscallArgs::Mprotect {
                addr: Pointer(args[0]),
                len: Size_T(args[1] as size_t),
                prot: Size_T(args[2] as i32 as size_t)
            })
        },
        SYSCALL_SANCOV_TRACE_PC => {
            let args = SyscallArgsGeneric
        }
        _ => Ok(SyscallArgs::Generic {})
    }
}