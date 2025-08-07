use cty::size_t;
use std::ffi::c_void;

use crate::ptrace_serialize::PtraceDeserialize;

use super::GuestPointer;

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GuestPCTableEntry {
    pc: GuestPointer<*const c_void>,
    flags: size_t,
}

impl PtraceDeserialize for GuestPCTableEntry {
    fn load_ptrace(
        tracee: &mut pete::Tracee,
        start: GuestPointer<*const c_void>,
        end: Option<GuestPointer<*const c_void>>,
    ) -> Result<Self, pete::Error>
    where
        Self: Sized,
    {
        let flags_addr = GuestPointer::<*const usize>::new(
            start
                .as_usize()
                .checked_add(std::mem::size_of::<usize>())
                .expect("we don't like overflows"),
        );

        let pc = GuestPointer::<*const c_void>::new(usize::load_ptrace(
            tracee,
            start.cast(),
            end.map(|x| x.cast()),
        )?);
        let flags = size_t::load_ptrace(tracee, flags_addr.cast(), end.map(|x| x.cast()))?;
        Ok(GuestPCTableEntry { pc, flags })
    }

    fn store_ptrace(
        &self,
        _: &mut pete::Tracee,
        _: GuestPointer<*mut c_void>,
    ) -> Result<(), pete::Error> {
        panic!("Cannot write back GuestPCTableEntry since they are stored in the read-only text segment.")
    }
}

impl PtraceDeserialize for Vec<GuestPCTableEntry> {
    fn load_ptrace(
        tracee: &mut pete::Tracee,
        start: GuestPointer<*const c_void>,
        end: Option<GuestPointer<*const c_void>>,
    ) -> Result<Self, pete::Error>
    where
        Self: Sized,
    {
        let elemsz = std::mem::size_of::<GuestPCTableEntry>();
        assert!(end.is_some());
        if let Some(endp) = end {
            assert!((endp.as_usize() - start.as_usize()) % elemsz == 0);
        }
        let end = end.unwrap();

        (start.as_usize()..end.as_usize())
            .step_by(elemsz)
            .map(|addr| {
                GuestPCTableEntry::load_ptrace(
                    tracee,
                    GuestPointer::<*const c_void>::new(addr),
                    Some(end),
                )
            })
            .collect::<Result<Vec<_>, _>>()
    }

    fn store_ptrace(
        &self,
        _: &mut pete::Tracee,
        _: GuestPointer<*mut c_void>,
    ) -> Result<(), pete::Error> {
        panic!("Cannot write back Vec<GuestPCTableEntry> since they are stored in the read-only text segment.")
    }
}
