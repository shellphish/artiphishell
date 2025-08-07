use pete::{Error, Tracee};

pub type Result<T> = std::result::Result<T, Error>;

pub trait SyscallArgsGenericExtractor<const N: usize> {
    fn extract(tracee: &mut Tracee) -> Result<SyscallArgsGeneric<N>>;
}
pub struct SyscallArgsGeneric<const N: usize> {
    pub args: [usize; N],
}
impl SyscallArgsGenericExtractor<0> for SyscallArgsGeneric<0> {
    fn extract(_: &mut Tracee) -> Result<SyscallArgsGeneric<0>> {
        Ok(SyscallArgsGeneric { args: [] })
    }
}
