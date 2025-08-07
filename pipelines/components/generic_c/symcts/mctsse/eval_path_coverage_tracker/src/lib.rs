#![feature(link_llvm_intrinsics)]
#![feature(core_intrinsics)]

use std::fmt;
use std::hash::{Hash,Hasher};
use std::collections::hash_map::DefaultHasher;
use libc::atexit;
use std::os::unix::net::UnixStream;
use std::io::prelude::*;
use prost::Message;

pub const SOCKET_PATH: &str = "/tmp/path_coverage_tracker";

#[macro_use]
mod util;
mod libshm;

pub mod counts {
    include!(concat!(env!("OUT_DIR"), "/path_coverage_tracker.counts.rs"));
}

use std::collections::HashMap;

#[derive(Hash,PartialEq,Eq,Copy,Clone)]
struct GuestPointer(i64);

impl fmt::Debug for GuestPointer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&format!("0x{:x}", self.0))
    }
}

impl From<GuestPointer> for i64 {
    fn from(t: GuestPointer) -> i64 {
        t.0
    }
}
impl From<i64> for GuestPointer {
    fn from(t: i64) -> GuestPointer {
        GuestPointer(t)
    }
}

fn write_out_results(state: GlobalState) {
    let to_serialize : counts::PerBranchPathCounts = counts::PerBranchPathCounts {
        ident: state.ident,
        counts_for_branch: state.path_hits.iter().map(
            |(&branch, value)| {
                (branch.into(), counts::PathCounts {
                    counts: value.clone(),
                })
            }).collect()
    };
    let mut encoded_buffer = Vec::<u8>::new();
    to_serialize.encode(&mut encoded_buffer).expect("Could not encode message into buffer!");
    //println!("{:?}", encoded_buffer);

    let mut stream = UnixStream::connect(SOCKET_PATH).expect(&format!("Could not open output stream socket @ {}!", SOCKET_PATH));
    let encoded_length: [u8; 8] = encoded_buffer.len().to_le_bytes();

    stream.write_all(&encoded_length).expect("Could not write out buffer length!");
    stream.write_all(&encoded_buffer[..]).expect("Could not write out protobuf message!");
}

extern "C" fn cleanup() {
    // eprintln!("Doing some final cleanup in atexit");
    libshm::cleanup_shm();
    let state = *unsafe { GLOBAL_STATE.take() }.unwrap(); // unsafe because mutable global vars are unsafe
    write_out_results(state);
}


static mut GLOBAL_STATE : Option<Box<GlobalState>> = None;

#[derive(Debug)]
struct GlobalState {
    ident: String,
    path : Vec<GuestPointer>,
    path_hits: HashMap<GuestPointer, HashMap<i64, i64>>,
}
fn init_globals() {
    let ident = std::env::var("COVERAGE_TRACKER_IDENT").unwrap();
    unsafe {
        GLOBAL_STATE.get_or_insert_with(|| {
            assert!(atexit(cleanup) == 0);
            Box::new(GlobalState {
                ident,
                path_hits: HashMap::new(),
                path: Vec::new(),
            })
        });
    }
}

fn calculate_hash<T: Hash>(t: &T) -> i64 {
    let mut s = DefaultHasher::new();
    t.hash(&mut s);
    s.finish() as i64
}

#[no_mangle]
#[export_name = "__sanitizer_cov_trace_pc"]
pub extern "C" fn __sanitizer_cov_trace_pc()
{
    init_globals();
    // __sanitizer_cov_trace_pc_guard does not seem to work as it ends up being statically linked into the binary
    let retaddr = retaddr!() as i64;
    let retaddr = GuestPointer(retaddr);
    println!("__sanitizer_cov_trace_pc: called from {:?}", retaddr);
    //libshm::inc_int64(i64::from(retaddr) % 3);
    unsafe {
        let glob = GLOBAL_STATE.as_mut().unwrap();
        glob.path.push(retaddr);
        let map = glob.path_hits.entry(retaddr).or_default();
        *map.entry(calculate_hash(&glob.path)).or_default() += 1;
        //println!("{:?}\n", GLOBAL_STATE.as_ref().unwrap().path_hits);
    }
}

#[no_mangle]
#[export_name = "map_shared_mem"]
pub extern "C" fn map_shared_mem(_: *const cty::c_char) {
    
}

#[no_mangle]
#[export_name = "report_numerical_coverage"]
pub extern "C" fn report_numerical_coverage(_: *const cty::c_void, id: cty::c_int) {
    init_globals();
    let retaddr = retaddr!() as i64;
    let retaddr = GuestPointer(retaddr);
    println!("report_numerical_coverage({}) called from {:?}", id, retaddr);
    //libshm::inc_int64(i64::from(retaddr) % 3);
    unsafe {
        let glob = GLOBAL_STATE.as_mut().unwrap();
        glob.path.push(retaddr);
        let map = glob.path_hits.entry(retaddr).or_default();
        *map.entry(calculate_hash(&glob.path)).or_default() += 1;
        //println!("{:?}\n", GLOBAL_STATE.as_ref().unwrap().path_hits);
    }
}
