use std::collections::HashSet;

use cty::c_void;
use pete::Tracee;
use sancov_shared::{
    guest_data_structures::{GuestPCTableEntry, GuestPointer},
    ptrace_serialize::PtraceDeserialize,
};

#[derive(Debug, Eq, PartialEq, Default)]
pub struct SanCovState {
    module_base: Option<GuestPointer<*const c_void>>,
    inline8_bit_counters: Option<(GuestPointer<*mut u8>, GuestPointer<*mut u8>)>,
    inline_bools: Option<(GuestPointer<*mut u8>, GuestPointer<*mut u8>)>,
    pc_guards: Option<(GuestPointer<*mut u32>, GuestPointer<*mut u32>)>,
    pcs_table: Option<(
        GuestPointer<*const GuestPCTableEntry>,
        GuestPointer<*const GuestPCTableEntry>,
    )>,
    indirect_calls: HashSet<(GuestPointer<*const c_void>, GuestPointer<*const c_void>)>,
    traced_pcs: Vec<GuestPointer<*const c_void>>,
}

#[derive(Eq, PartialEq)]
pub struct SanCovFinalState {
    module_base: Option<GuestPointer<*const c_void>>,
    inline_8bit_counters: Vec<u8>,
    inline_bools: Vec<bool>,
    pc_guards: Vec<u32>,
    pcs_table: Vec<GuestPCTableEntry>,
    indirect_calls: HashSet<(GuestPointer<*const c_void>, GuestPointer<*const c_void>)>,
    traced_pcs: Vec<GuestPointer<*const c_void>>,
}

impl std::fmt::Debug for SanCovFinalState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SanCovFinalState")
            .field("module_base", &self.module_base)
            .field("inline_8bit_counters", &self.inline_8bit_counters)
            .field("inline_bools", &self.inline_bools)
            .field("pc_guards", &self.pc_guards)
            .field("pcs_table", &self.pcs_table)
            .field("indirect_calls", &self.indirect_calls)
            .field("traced_pcs", &self.traced_pcs)
            .finish()
    }
}

impl SanCovState {
    pub fn new() -> SanCovState {
        Default::default()
    }

    pub fn finalize(self, tracee: &mut Tracee) -> SanCovFinalState {
        let inline_8bit_counters = if let Some((start, end)) = self.inline8_bit_counters {
            Vec::<u8>::load_ptrace(tracee, start.as_const().cast(), Some(end.as_const().cast()))
                .expect("Could not retrieve inline 8-bit counters")
        } else {
            vec![]
        };
        let inline_bools = if let Some((start, end)) = self.inline_bools {
            Vec::<u8>::load_ptrace(tracee, start.as_const().cast(), Some(end.as_const().cast()))
                .expect("Could not retrieve inline 8-bit counters")
                .into_iter()
                .map(|x| x != 0)
                .collect::<Vec<_>>()
        } else {
            vec![]
        };
        let pc_guards = if let Some((start, end)) = self.pc_guards {
            Vec::<u32>::load_ptrace(tracee, start.as_const().cast(), Some(end.as_const().cast()))
                .expect("Could not retrieve inline 8-bit counters")
        } else {
            vec![]
        };
        let pcs_table = if let Some((start, end)) = self.pcs_table {
            Vec::<GuestPCTableEntry>::load_ptrace(tracee, start.cast(), Some(end.cast()))
                .expect("Could not retrieve inline 8-bit counters")
        } else {
            vec![]
        };
        SanCovFinalState {
            module_base: self.module_base,
            inline_8bit_counters,
            inline_bools,
            pc_guards,
            pcs_table,
            indirect_calls: self.indirect_calls,
            traced_pcs: self.traced_pcs,
        }
    }

    pub fn register_inline_8bit_counters(
        &mut self,
        start: GuestPointer<*mut u8>,
        end: GuestPointer<*mut u8>,
    ) {
        assert!(start <= end);
        if let Some((old_start, old_end)) = self.inline8_bit_counters.replace((start, end)) {
            if old_start != start && old_end != end {
                panic!("Somehow the inline 8bit counters were registered multiple times????\nold: {:?}, new: {:?}",
                    (old_start, old_end),
                    (start, end)
                );
            }
        }
    }
    pub fn register_inline_bool_flags(
        &mut self,
        start: GuestPointer<*mut u8>,
        end: GuestPointer<*mut u8>,
    ) {
        assert!(start <= end);
        if let Some((old_start, old_end)) = self.inline_bools.replace((start, end)) {
            if old_start != start && old_end != end {
                panic!("Somehow the inline bool flags were registered multiple times????\nold: {:?}, new: {:?}",
                    (old_start, old_end),
                    (start, end)
                );
            }
        }
    }
    pub fn register_pc_guards(
        &mut self,
        start: GuestPointer<*mut u32>,
        end: GuestPointer<*mut u32>,
    ) {
        assert!(start <= end);
        if let Some((old_start, old_end)) = self.pc_guards.replace((start, end)) {
            if old_start != start && old_end != end {
                panic!("Somehow the pc guard entries were registered multiple times????\nold: {:?}, new: {:?}",
                    (old_start, old_end),
                    (start, end)
                );
            }
        }
    }
    pub fn register_module_base(&mut self, module_base: GuestPointer<*const c_void>) {
        if let Some(old_module_base) = self.module_base.replace(module_base) {
            if old_module_base != module_base {
                panic!("Somehow the module base was registered multiple times????\nold: {:?}, new: {:?}",
                    old_module_base,
                    module_base
                );
            }
        }
    }

    pub fn register_pcs_table(
        &mut self,
        start: GuestPointer<*const GuestPCTableEntry>,
        end: GuestPointer<*const GuestPCTableEntry>,
    ) {
        assert!(start <= end);
        if let Some((old_start, old_end)) = self.pcs_table.replace((start, end)) {
            if old_start != start && old_end != end {
                panic!(
                    "Somehow the pcs table was registered multiple times????\nold: {:?}, new: {:?}",
                    (old_start, old_end),
                    (start, end)
                );
            }
        }
    }

    pub fn register_indirect_call(
        &mut self,
        callsite: GuestPointer<*const c_void>,
        callee: GuestPointer<*const c_void>,
    ) {
        self.indirect_calls.insert((callsite, callee));
    }
    pub fn register_traced_pc(&mut self, pc: GuestPointer<*const c_void>) {
        self.traced_pcs.push(pc);
    }
}
