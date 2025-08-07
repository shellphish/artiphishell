//! A libfuzzer-like fuzzer with llmp-multithreading support and restarts
//! The example harness is built for `stb_image`.

#![feature(option_get_or_insert_default)]


use mimalloc::MiMalloc;
use symcts::standalone_cov_tracer::{Tracer, TraceResult};
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

use libafl_bolts::{
    rands::{StdRand, Rand},
};
use libafl::{
    prelude::ExitKind,
    inputs::{BytesInput, Input},
    Error,
};
use clap::{self, Parser};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// directory containing testcase
    #[clap()]
    directory: String,
    #[clap(num_args = 1..)]
    pub target_commandline: Vec<String>,
}

pub fn main() {
    let args = Args::parse();
    fuzz(args)
    .expect("An error occurred while fuzzing");
}

fn map_repr(map: &TraceResult) -> Vec<String> {
    match map {
        TraceResult::Uncompressed { observer_map } => {
            observer_map.iter()
                .enumerate()
                .filter_map(|(i, &x)| if x != 0 { Some(format!("0x{:x}:0x{:x}", i, x)) } else { None })
                .collect::<Vec<_>>()
        },
        TraceResult::Compressed { hit_vec, adjacent_vec, func_adjacent_vec } => {
            let mut result = Vec::new();
            assert!(hit_vec.len() == adjacent_vec.len() && adjacent_vec.len() == func_adjacent_vec.len());
            let mut print_positions = hit_vec.clone();
            print_positions |= adjacent_vec;
            print_positions |= func_adjacent_vec;
            for i in print_positions.iter_ones() {
                result.push(format!("0x{:x}: hit={:?}, adjacent={:?}, func_adjacent={:?}", i, hit_vec.get(i), adjacent_vec.get(i), func_adjacent_vec.get(i)));
            }
            result
        }
    }

}
fn diff_maps(map_one: &TraceResult, map_two: &TraceResult) -> Vec<String> {
    // map_one
    //     .iter()
    //     .zip(map_two.iter())
    //     .enumerate()
    //     .filter_map(|(i, (&x, &y))| if x != y { Some(format!("0x{:x}: 0x{:x} vs 0x{:x}", i, x, y)) } else { None })
    //     .collect::<Vec<_>>()

    match (map_one, map_two) {
        (TraceResult::Uncompressed { observer_map: map_one }, TraceResult::Uncompressed { observer_map: map_two }) => {
            map_one
                .iter()
                .zip(map_two.iter())
                .enumerate()
                .filter_map(|(i, (&x, &y))| if x != y { Some(format!("0x{:x}: 0x{:x} vs 0x{:x}", i, x, y)) } else { None })
                .collect::<Vec<_>>()
        },
        (TraceResult::Compressed { hit_vec: map_one, adjacent_vec: map_one_adjacent, func_adjacent_vec: map_one_func_adjacent }, TraceResult::Compressed { hit_vec: map_two, adjacent_vec: map_two_adjacent, func_adjacent_vec: map_two_func_adjacent }) => {
            let mut result = Vec::new();
            assert!(map_one.len() == map_two.len() && map_one_adjacent.len() == map_two_adjacent.len() && map_one_func_adjacent.len() == map_two_func_adjacent.len());
            let mut print_positions = map_one.clone();
            print_positions |= map_two.clone();
            print_positions |= map_one_adjacent.clone();
            print_positions |= map_two_adjacent.clone();
            print_positions |= map_one_func_adjacent.clone();
            print_positions |= map_two_func_adjacent.clone();
            for i in print_positions.iter_ones() {
                result.push(format!("0x{:x}: hit={:?}, adjacent={:?}, func_adjacent={:?} vs hit={:?}, adjacent={:?}, func_adjacent={:?}", i, map_one.get(i), map_one_adjacent.get(i), map_one_func_adjacent.get(i), map_two.get(i), map_two_adjacent.get(i), map_two_func_adjacent.get(i)));
            }
            result
        },
        _ => panic!("Cannot compare different map types")
    }
}

/// The actual fuzzer
fn fuzz(args: Args) -> Result<(), Error> {
    // 'While the stats are state, they are usually used in the broker - which is likely never restarted
    let mut rng = StdRand::with_seed(0);
    let mut tracer = Tracer::create(args.target_commandline.to_owned())?;

    // get all inputs in args.directory
    let inputs = std::fs::read_dir(&args.directory)?
        .into_iter()
        .filter_map(|entry| {
            let path = entry.expect("Could not read entry").path();
            if path.is_file() {
                let input = BytesInput::from_file(&path).expect("Could not load input");
                Some((path, input))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    let mut known_result: Vec<Option<(ExitKind, TraceResult)>> = vec![None; inputs.len()];
    for i in 0.. {
        // randomly select one of the inputs
        let rand_index = rng.below(inputs.len() as u64) as usize;
        // let rand_index = 0;
        let (input_path, _input) = &inputs[rand_index];

        let modified_timestamp = std::fs::metadata(input_path).unwrap().modified().unwrap();

        let trace_result = tracer.trace_input(input_path, modified_timestamp, false)?;
        let exit_kind = trace_result.exit_kind;
        println!("{i}: Input @ {rand_index} {input_path:?} -> {:?} {}", trace_result.exit_kind, map_repr(&trace_result.result).len());
        if known_result[rand_index].is_none() {
            known_result[rand_index] = Some((trace_result.exit_kind, trace_result.result));
            continue;
        }

        let (expected_exitkind, expected_result) = &known_result[rand_index].as_ref().unwrap();
        let matches = &exit_kind == expected_exitkind && expected_result == &trace_result.result;

        if !matches {
            println!("{}: Coverage for Input {} did not match: {}", i, rand_index, input_path.display());
            println!("Expected: {:?} {:?}", expected_exitkind, map_repr(&expected_result));
            println!("Actual:   {:?} {:?}", exit_kind, map_repr(&trace_result.result));
            println!("Diff: {:?}", diff_maps(&expected_result, &trace_result.result));
            println!("Known results: ");
            for (i, known_result) in known_result.iter().enumerate() {
                if let Some((exit_kind, map)) = known_result {
                    println!("{}: {:?} {:?}", i, exit_kind, map_repr(map));
                }
            }
            panic!("Coverage mismatch");
        }
        else {

        }
    }

    Ok(())
}