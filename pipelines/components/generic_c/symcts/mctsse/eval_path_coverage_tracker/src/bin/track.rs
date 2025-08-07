#![feature(iter_advance_by)]

use std::collections::HashMap;
use std::io::prelude::*;
use std::os::unix::net::{UnixStream,UnixListener};
use prost::Message;
use std::sync::{Arc,Mutex};
use std::io::Result;
use std::ops::DerefMut;
use std::fs::OpenOptions;
use std::{thread,fmt,time,fs};
use log::{debug,info,error};
use env_logger;

pub mod counts {
    include!(concat!(env!("OUT_DIR"), "/path_coverage_tracker.counts.rs"));
}

pub const SOCKET_PATH: &str = "/tmp/path_coverage_tracker";

type PathHash = i64;
type BranchId = String;
type BranchCount = i64;
type GlobalCounts = HashMap<String, HashMap<BranchId, HashMap<PathHash, BranchCount>>>;

#[derive(serde::Serialize, serde::Deserialize)]
struct Global(GlobalCounts);

impl fmt::Display for Global {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        for (ident, by_branch_counts) in &self.0 {
            writeln!(fmt, "NODE: {}", ident)?;
            for (branch, path_counts) in by_branch_counts {
                writeln!(fmt, "{}: {:?}", branch, path_counts)?;
            }
        }
        Ok(())
    }
}

fn handle_client(global_ref: Arc<Mutex<Global>>, mut stream: UnixStream) -> Result<()> {

    let mut len_buf = [0u8; 8];
    stream.read_exact(&mut len_buf)?;
    let msglen = u64::from_le_bytes(len_buf);
    let mut data_buf = vec![0u8; msglen as usize];
    stream.read_exact(&mut data_buf[..])?;
    let message = counts::PerBranchPathCounts::decode(&data_buf[..])?;

    let mut lock_guard = global_ref.lock().unwrap();
    let map: &mut Global = lock_guard.deref_mut();

    let by_branch_counts =  map.0.entry(message.ident).or_default();
    for (branch, path_counts) in &message.counts_for_branch {
        let branch_id = format!("0x{:x}", *branch as u64);
        let global_path_counts = by_branch_counts.entry(branch_id).or_default();
        for (path_id, count) in &path_counts.counts {
            let global_count = global_path_counts.entry(*path_id).or_default();
            *global_count += count;
        }
    }
    debug!("Receive client map: {}", map);
    Ok(())
}
fn append_to_file(path: &str, content: &str) {
    let mut file = OpenOptions::new()
        .write(true)
        .append(true)
        .create(true)
        .open(path)
        .unwrap();
    writeln!(file, "{}", content).unwrap();
    file.flush().unwrap();
}
fn main() -> Result<()> {
    let mut args_iter = std::env::args();
    args_iter.advance_by(1).unwrap();
    let out_path = args_iter.next().ok_or("You need to specify a filename to write the json results to.").unwrap();
    let log_ms: f64 = args_iter.next().ok_or("You need to specify the logging interval").unwrap().parse::<f64>().unwrap();
    let node_names : Vec<String> = args_iter.collect();
    assert!(!node_names.is_empty());

    env_logger::init();

    let per_branch_global_count: Arc<Mutex<Global>> = Arc::new(Mutex::new(Global(Default::default())));

    if fs::remove_file(SOCKET_PATH).is_ok() {
        info!("Deleted old socket {}", &SOCKET_PATH);
    };
    if fs::remove_file(&out_path).is_ok() {
        info!("Deleted old file {}", &out_path);
    };
    info!("{:?}", node_names);

    let writer_global_ref = Arc::clone(&per_branch_global_count);
    thread::spawn(move || {
        let mut seconds_since_start: f64 = 0.0;
        loop {
            info!("Sleeping for {} seconds", log_ms);
            thread::sleep(time::Duration::from_secs_f64(log_ms));
            seconds_since_start += log_ms;

            info!("Writing out results!");
            let content = {
                let glob : &Global = &writer_global_ref.lock().unwrap();
                serde_json::to_string(glob).unwrap()
            };
            debug!("Content: {}", content);
            let path = format!("{}.{}secs", out_path, seconds_since_start);
            // append_to_file(&path, &serde_json::to_string(&node_names).unwrap());
            append_to_file(&path, &content);
        }
    });
    let listener = UnixListener::bind(SOCKET_PATH)?;
    for stream in listener.incoming() {
        let stream = stream.unwrap();
        let global_ref = Arc::clone(&per_branch_global_count);
        std::thread::spawn(move || {
            handle_client(global_ref, stream).unwrap();
        });

    }
    Ok(())
}