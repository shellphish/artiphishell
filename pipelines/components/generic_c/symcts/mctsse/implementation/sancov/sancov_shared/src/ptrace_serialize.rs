use crate::guest_data_structures::GuestPointer;
use cty::c_void;
use pete::{Error, Tracee};

pub trait PtraceDeserialize {
    fn load_ptrace(
        tracee: &mut Tracee,
        start: GuestPointer<*const c_void>,
        end: Option<GuestPointer<*const c_void>>,
    ) -> Result<Self, Error>
    where
        Self: Sized;
    fn store_ptrace(
        &self,
        tracee: &mut Tracee,
        addr: GuestPointer<*mut c_void>,
    ) -> Result<(), Error>;
}

macro_rules! primitive_int {
    ($t:ty) => {
        impl PtraceDeserialize for $t {
            fn load_ptrace(tracee: &mut Tracee, start: GuestPointer<*const c_void>, end: Option<GuestPointer<*const c_void>>) -> Result<$t, Error> {
                let sz = std::mem::size_of::<$t>();
                if let Some(endp) = end {
                    assert!(endp.as_usize() - start.as_usize() >= sz);
                }
                let buf = tracee.read_memory(start.as_usize() as u64, sz)?;
                let (int_bytes, rest) = buf.split_at(sz);
                assert!(rest.len() == 0);
                Ok(<$t>::from_ne_bytes(int_bytes.try_into().unwrap()))
            }
            fn store_ptrace(&self, tracee: &mut Tracee, addr: GuestPointer<*mut c_void>) -> Result<(), Error> {
                let bytes = self.to_ne_bytes();
                let written = tracee.write_memory(addr.as_usize() as u64, &bytes)?;
                assert!(written == bytes.len());
                Ok(())
            }
        }
        impl PtraceDeserialize for Vec<$t> {
            fn load_ptrace(tracee: &mut Tracee, start: GuestPointer<*const c_void>, end: Option<GuestPointer<*const c_void>>) -> Result<Vec<$t>, Error> {
                let elemsz = std::mem::size_of::<$t>();
                assert!(end.is_some());
                if let Some(endp) = end {
                    assert!((endp.as_usize() - start.as_usize()) % elemsz == 0);
                }
                let end = end.unwrap();

                (start.as_usize()..end.as_usize())
                    .step_by(elemsz)
                    .map(|addr| {
                        <$t>::load_ptrace(tracee, GuestPointer::<*const c_void>::new(addr), Some(end))
                    }).collect::<Result<Vec<_>, _>>()
            }
            fn store_ptrace(&self, tracee: &mut Tracee, addr: GuestPointer<*mut c_void>) -> Result<(), Error> {
                self.iter()
                    .enumerate()
                    .try_for_each(
                        |(i, elem)| {
                            let addr: GuestPointer<*mut $t> = addr
                                .cast::<$t>()
                                .offset(i.try_into().unwrap());
                            elem.store_ptrace(tracee, addr.cast())
                        }
                    )
            }
        }
    };
    ($t:ty, $($ts:ty),+) => {
        primitive_int!($t);
        primitive_int!($($ts),+);
    }
}

primitive_int!(i8, i16, i32, i64, isize);
primitive_int!(u8, u16, u32, u64, usize);
