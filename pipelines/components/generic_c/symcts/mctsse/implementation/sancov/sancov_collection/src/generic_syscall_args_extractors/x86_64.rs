use pete::Tracee;

use crate::syscall_args_generic::{Result, SyscallArgsGeneric, SyscallArgsGenericExtractor};

impl SyscallArgsGenericExtractor<1> for SyscallArgsGeneric<1> {
    fn extract(tracee: &mut Tracee) -> Result<SyscallArgsGeneric<1>> {
        let regs = tracee.registers()?;
        Ok(SyscallArgsGeneric {
            args: [regs.rdi as usize],
        })
    }
}
impl SyscallArgsGenericExtractor<2> for SyscallArgsGeneric<2> {
    fn extract(tracee: &mut Tracee) -> Result<SyscallArgsGeneric<2>> {
        let regs = tracee.registers()?;
        Ok(SyscallArgsGeneric {
            args: [regs.rdi as usize, regs.rsi as usize],
        })
    }
}
impl SyscallArgsGenericExtractor<3> for SyscallArgsGeneric<3> {
    fn extract(tracee: &mut Tracee) -> Result<SyscallArgsGeneric<3>> {
        let regs = tracee.registers()?;
        Ok(SyscallArgsGeneric {
            args: [regs.rdi as usize, regs.rsi as usize, regs.rdx as usize],
        })
    }
}
impl SyscallArgsGenericExtractor<4> for SyscallArgsGeneric<4> {
    fn extract(tracee: &mut Tracee) -> Result<SyscallArgsGeneric<4>> {
        let regs = tracee.registers()?;
        Ok(SyscallArgsGeneric {
            args: [
                regs.rdi as usize,
                regs.rsi as usize,
                regs.rdx as usize,
                regs.r10 as usize,
            ],
        })
    }
}
impl SyscallArgsGenericExtractor<5> for SyscallArgsGeneric<5> {
    fn extract(tracee: &mut Tracee) -> Result<SyscallArgsGeneric<5>> {
        let regs = tracee.registers()?;
        Ok(SyscallArgsGeneric {
            args: [
                regs.rdi as usize,
                regs.rsi as usize,
                regs.rdx as usize,
                regs.r10 as usize,
                regs.r8 as usize,
            ],
        })
    }
}
impl SyscallArgsGenericExtractor<6> for SyscallArgsGeneric<6> {
    fn extract(tracee: &mut Tracee) -> Result<SyscallArgsGeneric<6>> {
        let regs = tracee.registers()?;
        Ok(SyscallArgsGeneric {
            args: [
                regs.rdi as usize,
                regs.rsi as usize,
                regs.rdx as usize,
                regs.r10 as usize,
                regs.r8 as usize,
                regs.r9 as usize,
            ],
        })
    }
}
