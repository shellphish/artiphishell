//! A libfuzzer-like fuzzer with llmp-multithreading support and restarts
//! The example harness is built for `stb_image`.

#![feature(option_get_or_insert_default)]

use std::path::PathBuf;

use clap::{self, Parser};
use symcts::disk_backed_concolic_metadata::DiskBackedConcolicMetadata;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// directory containing testcase
    #[clap()]
    trace_path: PathBuf,
}

pub fn main() {
    let args = Args::parse();
    let trace_path = args.trace_path;
    // let trace_content = std::fs::read(trace_path).unwrap();
    let meta = DiskBackedConcolicMetadata::for_path(trace_path);
    let last_id = meta.iter_messages().last().unwrap().0;
    let msgs = meta.iter_messages();

    for (id, msg) in msgs {
        println!("{:x}/{:x}: {:x?}", id, last_id, msg);
    }
}