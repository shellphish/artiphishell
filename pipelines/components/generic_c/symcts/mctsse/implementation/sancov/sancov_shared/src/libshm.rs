use shared_memory::{Shmem, ShmemConf};
use std::sync::Mutex;
// use std::sync::atomic::AtomicPtr;

static mut SHMEM: Option<Mutex<Box<Shmem>>> = None;
static mut SHMP: *mut u8 = 0 as *mut u8;

#[inline]
fn open_shm() -> Shmem {
    let shm_id: String = std::env::var("SHMEM_ID")
        .expect("Could not find the shared memory id in the environment. Please set SHMEM_ID.");
    let shm = ShmemConf::new().os_id(shm_id);
    shm.open().expect("Could not open shared memory mapping!")
}

#[inline]
fn initialize_shm() -> () {
    unsafe {
        SHMEM.get_or_insert_with(|| {
            let shmem = open_shm();
            SHMP = shmem.as_ptr();
            Mutex::new(Box::new(shmem))
        });
    }
}
#[inline]
pub fn cleanup_shm() -> () {
    unsafe {
        SHMEM.take();
        SHMP = 0 as *mut u8;
    }
}
#[inline]
fn getp() -> *mut u8 {
    initialize_shm();
    unsafe { SHMP }
}

#[inline]
pub fn inc_int64(val: u64) {
    unsafe {
        let p = getp() as *mut u64;
        let p_off = p.offset(val as isize);
        println!("SHMP: {:?}, writing to {:?}", p, p_off);
        let old = *p_off;
        std::intrinsics::atomic_cxchg(p_off, old, old + 1);
    }
}
