#[cfg(all(feature = "mode_ptrace", feature = "mode_shm"))]
compile_error!("You can only have either ptrace or shared memory mode enabled, not both!");

#[cfg(feature = "mode_ptrace")]
pub mod inst_ptrace;
#[cfg(feature = "mode_shm")]
pub mod inst_shm;
mod util;
