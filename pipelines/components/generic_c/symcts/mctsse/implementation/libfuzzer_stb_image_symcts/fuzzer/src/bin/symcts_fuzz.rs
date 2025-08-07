//! A libfuzzer-like fuzzer with llmp-multithreading support and restarts
//! The example harness is built for `stb_image`.

#![feature(option_get_or_insert_default)]

use clap::Parser;

use mimalloc::MiMalloc;
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

use serde::{Deserialize, Serialize};
use symcts::{coverage::SyMCTSCoverageFeedback, metadata::global::SyMCTSGlobalMetadata, reproducibility_details::{dump_build_details, dump_binary_and_deps}, util::{hash_bytes, ensure_baseline_inputs_exist}};
use std::{
    path::{PathBuf, Path},
    time::Duration, io::Write,
};
use symcts::symcts_scheduler::SyMCTSScheduler;

use libafl_bolts::{
    current_nanos,
    rands::StdRand,
    shmem::{ShMem, ShMemProvider, StdShMemProvider},
    tuples::tuple_list,
    AsMutSlice
};
use libafl::{
    corpus::{Corpus, OnDiskCorpus, CachedOnDiskCorpus},
    feedbacks::CrashFeedback,
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::BytesInput,
    observers::concolic::serialization_format::DEFAULT_SIZE,
    stages::StdMutationalStage,
    state::{HasCorpus, HasMetadata, StdState},
    Error, prelude::{TimeoutForkserverExecutor, StdMapObserver, ForkserverExecutor, StdScheduledMutator, havoc_mutations, RestartingMgr, tui::{TuiMonitor, ui::TuiUI}, MultiMonitor},
};

// parse cmdline args with clap
#[derive(Parser, Serialize, Deserialize, Debug, Clone)]
#[clap(version = "0.1", author = "Lukas Dresel", about = "A concolic-execution based fuzzer with constraint sampling")]
pub struct SyMCTSArgs {
    // the input directory containing the initial corpus
    #[clap(short, long, default_value = "corpus")]
    pub input_corpus: PathBuf,

    // The sync directory containing both our and other fuzzer's sync directories
    #[clap(short, long, default_value = "sync")]
    pub sync_dir: PathBuf,

    #[clap(short, long)]
    pub name: Option<String>,

    // the broker port
    #[clap(short, long, default_value = "1337")]
    pub broker_port: u16,

    #[clap(long, help="Path to the coverage collection harness compiled with our AFL++ instrumentation.")]
    pub afl_coverage_target: PathBuf,

    // flag for a dry run only
    #[clap(short, long)]
    pub dry_run: bool,

    // the command line with args to fuzz
    #[clap(num_args = ..)]
    pub target_args: Vec<String>,
}

pub fn main() -> Result<(), Error> {

    env_logger::init();

    let args = SyMCTSArgs::parse();
    let pid = std::process::id();

    let sync_dir = args.sync_dir.clone();
    let name = args.name.clone().unwrap_or_else(|| format!("symcts_fuzz_{}", pid));
    let my_sync_dir = sync_dir.join(name.clone());
    std::fs::create_dir_all(&my_sync_dir).unwrap();
    let my_sync_dir_absolute = std::fs::canonicalize(&my_sync_dir).unwrap();

    // create a symlink to this at {sync_dir}/symcts_latest, remove if previous exists
    let latest_symlink = sync_dir.join("symcts_latest");
    if latest_symlink.exists() {
        std::fs::remove_file(&latest_symlink).unwrap();
    }
    std::os::unix::fs::symlink(&my_sync_dir_absolute, &latest_symlink).unwrap();

    #[cfg(feature="dump_reproducibility_info")]
    {
        dump_build_details(&my_sync_dir);
        dump_run_info(&my_sync_dir, &args);
    }

    let crashes_dir = my_sync_dir.join("crashes");
    let corpus_dir = my_sync_dir.join("queue");

    // 'While the stats are state, they are usually used in the broker - which is likely never restarted
    let monitor = MultiMonitor::new(|s| println!("{}", s));
    // let monitor = TuiMonitor::new   (TuiUI::new("symcts_fuzz".to_string(), true));

    let (state, mut manager) = RestartingMgr::builder()
        .shmem_provider(StdShMemProvider::new()?)
        .monitor(Some(monitor))
        .broker_port(args.broker_port)
        .configuration(libafl::prelude::EventConfig::FromName { name_hash: hash_bytes(name.as_bytes()) })
        .serialize_state(true)
        .build()
        .launch()
        .expect("Could not start manager");

    println!("Restarting manager started: {:?}, {:?}", state, manager);

    let mut shmem_provider = StdShMemProvider::new().unwrap();
    const MAP_SIZE: usize = 65536 * 16;
    std::env::set_var("AFL_MAP_SIZE", MAP_SIZE.to_string());
    let mut afl_shm = shmem_provider.new_shmem(MAP_SIZE).unwrap();
    afl_shm.write_to_env("__AFL_SHM_ID").unwrap();
    let afl_shm_id = afl_shm.id().to_string();


    let symcts_env_extras_cov = std::env::vars().filter_map(|(key, value)| {
        if key.starts_with("SYMCTS_ENV_COV_") {
            Some((key.to_owned().strip_prefix("SYMCTS_ENV_COV_").unwrap().to_owned(), value))
        } else {
            None
        }
    }).collect::<Vec<_>>();

    let (mut feedback, mut cov_executor) = {

        // The coverage observer observers the coverage shared memory map.
        let slice_of_u8s = afl_shm.as_mut_slice();
        // convert slice to slice of u32s
        let slice_of_u32s = unsafe {
            std::slice::from_raw_parts_mut(
                slice_of_u8s.as_mut_ptr() as *mut u32,
                slice_of_u8s.len() / std::mem::size_of::<u32>(),
            )
        };
        let afl_map_observer = unsafe {
            StdMapObserver::new("afl_map", slice_of_u32s)
        };

        let symcts_feedback = SyMCTSCoverageFeedback::for_afl_bitmap_observer(&afl_map_observer);

        let coverage_executor = ForkserverExecutor::builder()
            .program(&args.afl_coverage_target)
            .debug_child(std::env::var("SYMCTS_DEBUG_FORKSERVER").is_ok())
            .shmem_provider(&mut shmem_provider)
            .env("AFL_DEBUG", "1")
            .env("__AFL_SHM_ID", afl_shm_id)
            .env("AFL_MAP_size", DEFAULT_SIZE.to_string())
            .env("__AFL_OUT_DIR", "/tmp/afl_out")
            .envs(symcts_env_extras_cov.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .is_persistent(true)
            .parse_afl_cmdline(&args.target_args)
            .build_dynamic_map(afl_map_observer, tuple_list!())?;

        log::debug!("Coverage executor: {:?}", coverage_executor);

        let coverage_executor = TimeoutForkserverExecutor::new(coverage_executor, Duration::from_millis(1000))?;

        (symcts_feedback, coverage_executor)
    };

    // A feedback to choose if an input is a solution or not
    let mut objective = CrashFeedback::new();

    // A minimization+queue policy to get testcasess from the corpus
    let symcts_scheduler = SyMCTSScheduler::new();

    // If not restarting, create a State from scratch
    let mut state = state.unwrap_or_else(|| StdState::new(
            // RNG
            StdRand::with_seed(current_nanos()),

            // corpus with seeds
            CachedOnDiskCorpus::<BytesInput>::no_meta(
                corpus_dir.clone(),
                256)
                    .expect("Could not create corpus)"),

            // Corpus in which we store solutions (crashes in this example),
            // on disk so the user can get them after stopping the fuzzer
            OnDiskCorpus::new(crashes_dir).unwrap(),
            // States of the feedbacks.
            // The feedbacks can report the data that should persist in the State.
            &mut feedback,
            // Same for objective feedbacks
            &mut objective,
        )
        .unwrap()
    );
    let mut global_meta = SyMCTSGlobalMetadata::default();
    global_meta.sync_dir = my_sync_dir.clone();
    state.add_metadata(global_meta);

    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(symcts_scheduler, feedback, objective);

    std::fs::create_dir_all("/tmp/afl_out/").unwrap();

    // log::info!("Creating baseline inputs in {:?}", &args.input_corpus);
    ensure_baseline_inputs_exist(&args.input_corpus).unwrap();
    // eprintln!("Done creating baseline inputs");
    // flush stderr
    std::io::stderr().flush().unwrap();

    if state.corpus().count() < 1 {
        let input_dirs = vec![args.input_corpus.clone()];
        state
            .load_initial_inputs(
                &mut fuzzer,
                &mut cov_executor,
                &mut manager,
                &input_dirs,
            )
            .expect(format!("Could not load initial inputs from {:?}", input_dirs).as_str());
        println!(
            "We imported {} inputs from disk. Annotating ...",
            state.corpus().count()
        );
        assert!(state.corpus().count() > 0);
        println!(
            "We imported {} inputs from disk. Annotating ...",
            state.corpus().count()
        );
    }

    // The order of the stages matter!

    let mut stages = tuple_list!(
        StdMutationalStage::new(StdScheduledMutator::new(havoc_mutations())),
    );

    if !args.dry_run {
        fuzzer.fuzz_loop(
            &mut stages,
            &mut cov_executor,
            &mut state,
            &mut manager,
        )?;
    }
    else {
        println!("Dry run, not fuzzing: {:?}", &args);
    }
    // Never reached
    Ok(())
}

fn dump_run_info(my_sync_dir: &PathBuf, args: &SyMCTSArgs) {
    let bin_dir = my_sync_dir.join(".run_info");
    std::fs::create_dir_all(&bin_dir).unwrap();

    // first, dump the passed arguments
    let mut f = std::fs::File::create(bin_dir.join("args.json")).unwrap();
    serde_json::to_writer_pretty(&mut f, &args).unwrap();

    // then, recursively copy the input corpus directory to {bin_dir}/input_corpus
    let input_corpus_dir = bin_dir.join("input_corpus/");
    // use cp
    let mut cmd = std::process::Command::new("cp");
    cmd
        .arg("-r")
        .arg(&format!("{}/", &args.input_corpus.display()))
        .arg(&input_corpus_dir);
    cmd.status()
        .expect("Failed to copy input corpus");


    dump_binary_and_deps(&bin_dir.join("cov_bin"), Path::new(&args.afl_coverage_target));
}
