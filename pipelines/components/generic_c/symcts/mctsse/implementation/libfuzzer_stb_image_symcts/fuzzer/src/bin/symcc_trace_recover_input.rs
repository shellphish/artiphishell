//! A libfuzzer-like fuzzer with llmp-multithreading support and restarts
//! The example harness is built for `stb_image`.

#![feature(option_get_or_insert_default)]

use std::{path::PathBuf, io::Write};

use clap::{self, Parser};
use libafl::observers::concolic::SymExpr;
use symcts::disk_backed_concolic_metadata::DiskBackedConcolicMetadata;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// directory containing testcase
    #[clap()]
    trace_path: PathBuf,
    #[clap()]
    out_path: PathBuf,
}

pub fn main() {
    let args = Args::parse();
    let trace_path = args.trace_path;
    // let trace_content = std::fs::read(trace_path).unwrap();
    let meta = DiskBackedConcolicMetadata::for_path(trace_path);
    let msgs = meta.iter_messages();

    let mut input = Vec::<u8>::new();

    for (_id, msg) in msgs {
        if let SymExpr::InputByte { offset, value } = msg {
            if input.len() < offset + 1 {
                input.resize(offset + 1, 0);
            }
            input[offset] = value;
        }
    }

    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .open(args.out_path)
        .unwrap()
        .write_all(&input)
        .unwrap();
}