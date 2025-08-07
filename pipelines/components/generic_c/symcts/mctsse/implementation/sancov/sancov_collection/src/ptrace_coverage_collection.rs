use pete::{self, Pid, Ptracer, Restart, Signal, Stop};
use sancov_shared::sancov_ptrace_interface::is_sancov_syscall;
use std::{
    collections::BTreeMap,
    process::{Child, Command},
    thread,
};
use syscall_numbers::native::sys_call_name;

use crate::{
    sancov_state::{SanCovFinalState, SanCovState},
    syscall_args_sancov::{extract_sancov_syscall_args, SancovSyscallArgs},
};

type Result<T> = std::result::Result<T, pete::Error>;

#[derive(Debug, Eq, PartialEq)]
pub enum TraceResult {
    Exit {
        exit_code: i32,
        coverage: SanCovFinalState,
    },
    Signal {
        signal: Signal,
        core_dumped: bool,
        coverage: SanCovFinalState,
    },
}
pub fn collect_sancov_ptrace<F>(cmd: Command, interaction_func: F) -> Result<TraceResult>
where
    F: FnOnce(Child) + Send + 'static,
{
    let mut tracer = Ptracer::new();
    let child = tracer.spawn(cmd)?;
    let joinhandle = thread::spawn(move || {
        interaction_func(child);
    });

    let mut pending_syscalls: BTreeMap<Pid, (u64, SancovSyscallArgs)> = BTreeMap::new();
    let mut sancov_state = SanCovState::new();

    while let Some(mut tracee) = tracer.wait()? {
        match tracee.stop {
            Stop::SyscallEnter => {
                let regs = tracee.registers().unwrap();
                let sysno = regs.orig_rax;

                if let Some(sancov_args) = extract_sancov_syscall_args(&mut tracee)? {
                    pending_syscalls.insert(tracee.pid, (sysno, sancov_args));
                }
            }
            Stop::SyscallExit => {
                let mut registers = tracee.registers()?;
                let sysno = registers.orig_rax;
                if is_sancov_syscall(sysno.try_into().unwrap()) {
                    let syscall_name = sys_call_name(sysno as i64)
                        .map(String::from)
                        .or_else(|| Some(format!("SYS_0x{:x}", sysno)))
                        .unwrap();

                    let (enter_sysno, enter_args) = pending_syscalls
                        .remove(&tracee.pid)
                        .expect("how did we exit a syscall we never entered??");
                    assert!(
                        sysno == enter_sysno,
                        "How did we end up exiting syscall #{} after entering #{}",
                        sysno,
                        enter_sysno
                    );
                    println!("{}[{}]: {:?}", syscall_name, sysno, &enter_args);

                    registers.rax = 0; // default: success, return 0
                    match enter_args {
                        SancovSyscallArgs::TracePc { callsite } => {
                            sancov_state.register_traced_pc(callsite);
                        }
                        SancovSyscallArgs::TracePcGuard {
                            guard: _,
                            guard_val,
                            callsite: _,
                        } => {
                            registers.rax = (guard_val + 1).try_into().unwrap();
                        }
                        SancovSyscallArgs::CaptureInline8BitCountersTable { start, end } => {
                            sancov_state.register_inline_8bit_counters(start, end);
                        }
                        SancovSyscallArgs::CaptureInlineBoolsTable { start, end } => {
                            sancov_state.register_inline_bool_flags(start, end);
                        }
                        SancovSyscallArgs::CapturePcGuardsTable { start, end } => {
                            sancov_state.register_pc_guards(start, end);
                            let num_bytes = end.as_usize().checked_sub(start.as_usize()).unwrap();
                            let data = vec![1; num_bytes];
                            tracee.write_memory(start.as_usize() as u64, &data)?;
                        }
                        SancovSyscallArgs::CapturePcsTable {
                            module_start,
                            start,
                            end,
                        } => {
                            sancov_state.register_module_base(module_start);
                            sancov_state.register_pcs_table(start, end);
                        }
                    }
                    tracee.set_registers(registers)?;
                }
            }
            Stop::Exiting { exit_code } => {
                // println!("Exiting process with exit_code {:?}", exit_code);
                // let regs = tracee.registers().unwrap();
                // println!("regs: rax=0x{:x} rdi=0x{:x} rip=0x{:x}", regs.rax, regs.rdi, regs.rip);
                // println!("Code @ rip = {:?}", tracee.read_memory(regs.rip, 10));
                let final_sancov_state = sancov_state.finalize(&mut tracee);

                assert!(
                    pending_syscalls.is_empty(),
                    "How did we end up with pending syscalls?"
                );
                joinhandle
                    .join()
                    .expect("Must be able to join on interaction thread!");
                return Ok(TraceResult::Exit {
                    exit_code,
                    coverage: final_sancov_state,
                });
            }
            Stop::Signaling {
                signal,
                core_dumped,
            } => {
                // let regs = tracee.registers().unwrap();
                // println!("Process died to a signal: signal={:?} core_dumped={:?}", signal, core_dumped);
                // println!("regs: rax=0x{:x} rdi=0x{:x} rip=0x{:x}", regs.rax, regs.rdi, regs.rip);
                // println!("Code @ rip = {:?}", tracee.read_memory(regs.rip, 10));
                let final_sancov_state = sancov_state.finalize(&mut tracee);

                assert!(
                    pending_syscalls.is_empty(),
                    "How did we end up with pending syscalls?"
                );
                joinhandle
                    .join()
                    .expect("Must be able to join on interaction thread!");
                println!("Final sancov state: {:#?}", &final_sancov_state);
                return Ok(TraceResult::Signal {
                    signal,
                    core_dumped,
                    coverage: final_sancov_state,
                });
            }
            Stop::SignalDelivery { signal: _ } => {
                // println!("Child process received signal {:?}", signal);
                // let regs = tracee.registers().unwrap();
                // println!("regs: rax=0x{:x} rdi=0x{:x} rip=0x{:x}", regs.rax, regs.rdi, regs.rip);
                // println!("Code @ rip = {:?}", tracee.read_memory(regs.rip, 10));
            }

            Stop::Attach => todo!(),
            Stop::Group { signal: _ } => todo!(),
            Stop::Clone { new: _ } => todo!(),
            Stop::Fork { new: _ } => todo!(),
            Stop::Exec { old: _ } => todo!(),
            Stop::Vfork { new: _ } => todo!(),
            Stop::VforkDone { new: _ } => todo!(),
            Stop::Seccomp { data: _ } => todo!(),
        }
        tracer.restart(tracee, Restart::Syscall).unwrap();
    }
    unreachable!()
}
