use std::ffi::CString;

use cty::c_void;

use crate::guest_data_structures::GuestPointer;
use crate::ptrace_serialize::PtraceDeserialize;
use crate::util::align_up;

#[derive(Eq, PartialEq, Ord, PartialOrd)]
pub struct GuestCString(pub CString);

const ALIGNMENT: usize = 0x100;

impl PtraceDeserialize for GuestCString {
    fn load_ptrace(
        tracee: &mut pete::Tracee,
        start: GuestPointer<*const c_void>,
        end: Option<GuestPointer<*const c_void>>,
    ) -> Result<GuestCString, pete::Error> {
        let start = start.as_usize();
        let end = end.map(|x| x.as_usize());

        let mut mem = if let Some(end) = end {
            assert!(end >= start);
            tracee.read_memory(start as u64, end - start as usize)?
        } else {
            let mut vec: Vec<u8> = vec![];
            let start_aligned = align_up(start, ALIGNMENT);
            vec.append(&mut tracee.read_memory(start as u64, start_aligned - start)?);
            if !vec.contains(&0u8) {
                loop {
                    let mut new = tracee.read_memory((start + vec.len()) as u64, ALIGNMENT)?;
                    if new.contains(&0u8) {
                        break;
                    }
                    vec.append(&mut new);
                }
            }
            vec
        };
        let null_byte_pos = mem
            .iter()
            .position(|x| *x == 0)
            .expect("this should always have a null byte??");

        mem.truncate(null_byte_pos + 1);
        Ok(GuestCString(
            CString::from_vec_with_nul(mem).expect("this should always work here?????"),
        ))
    }
    fn store_ptrace(
        &self,
        tracee: &mut pete::Tracee,
        addr: GuestPointer<*mut c_void>,
    ) -> Result<(), pete::Error> {
        let vec = self.0.as_bytes_with_nul();
        let written = tracee.write_memory(addr.as_usize() as u64, vec)?;
        assert!(written == vec.len());
        Ok(())
    }
}

impl std::fmt::Debug for GuestCString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if f.alternate() {
            write!(f, "{:?}", self.0.to_str().unwrap())
        } else {
            match self.0.to_str() {
                Ok(v) => write!(f, "{:?}", v),
                Err(_) => write!(f, "Non-utf8({:?})", self.0),
            }
        }
    }
}
