//! A libfuzzer-like fuzzer with llmp-multithreading support and restarts
//! The example harness is built for `stb_image`.

#![feature(option_get_or_insert_default)]

use clap::Parser;

#[cfg(not(feature = "dhat-heap"))]
use mimalloc::MiMalloc;
#[cfg(not(feature = "dhat-heap"))]
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[cfg(feature = "dhat-heap")]
use dhat;
#[cfg(feature = "dhat-heap")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

use serde::{Deserialize, Serialize};
#[cfg(feature="dhat-heap")]
use signal_hook::{iterator::Signals, consts::{SIGUSR1, SIGUSR2}};
#[cfg(feature="dhat-heap")]
use std::thread;
use symcts::{coverage::SyMCTSCoverageFeedback, metadata::{global::SyMCTSGlobalMetadata, solve_stats::SymbolicSolveStats}, reproducibility_details::{dump_build_details, dump_binary_and_deps}, util::hash_bytes, concolic_synchronization::handle_concolic_execution_event};
use std::{
    path::{PathBuf, Path},
    process::{Child, Command, Stdio, exit}, io::Write, time::Duration, str::FromStr,
};
use symcts::symcts_mutational_stage::SyMCTSMutationalStage;
use symcts::symcts_scheduler::SyMCTSScheduler;
use symcts::util::ensure_baseline_inputs_exist;

use libafl_bolts::{
    current_nanos,
    rands::StdRand,
    shmem::{ShMem, ShMemProvider, StdShMemProvider},
    tuples::tuple_list,
    AsSlice, AsMutSlice, Named
};
use libafl::{
    corpus::{Corpus, OnDiskCorpus, CachedOnDiskCorpus},
    executors::command::CommandConfigurator,
    feedbacks::CrashFeedback,
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::{BytesInput, HasTargetBytes, Input},
    monitors::MultiMonitor,
    observers::{
        concolic::{
            serialization_format::{DEFAULT_ENV_NAME, DEFAULT_SIZE},
            ConcolicObserver,
        }, TimeObserver,
    },
    stages::{
        ConcolicTracingStage, TracingStage
    },
    state::{HasCorpus, HasMetadata, StdState},
    Error, prelude::{TimeoutForkserverExecutor, StdMapObserver, ForkserverExecutor, setup_restarting_mgr_std, HasCustomBufHandlers},
};

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum ConcolicExecutionMode {
    SymCC,
    SymQEMU,
}
impl FromStr for ConcolicExecutionMode {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "symcc" => Ok(ConcolicExecutionMode::SymCC),
            "symqemu" => Ok(ConcolicExecutionMode::SymQEMU),
            _ => Err(Error::illegal_argument(format!("Unknown concolic execution mode: {}", s))),
        }
    }
}

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

    #[clap(long, help="Path to the target compiled without instrumentation, for use with (sym)qemu.")]
    pub vanilla_target: Option<PathBuf>,

    #[clap(long, help="Path to the concolic execution harness compiled with symcc instrumentation.")]
    pub symcc_target: Option<PathBuf>,

    #[clap(long, help="Path to the symqemu binary to use alongside the `--vanilla-harness`")]
    pub symqemu: Option<PathBuf>,

    #[cfg(not(feature="mutation_mode_fuzzing"))]
    #[clap(long, help="Concolic execution mode to use. Either `symcc` or `symqemu`.", default_value = "symcc")]
    pub concolic_execution_mode: ConcolicExecutionMode,

    // flag for a dry run only
    #[clap(short, long)]
    pub dry_run: bool,

    // the command line with args to fuzz
    #[clap(num_args = ..)]
    pub target_args: Vec<String>,
}

/// The actual fuzzer
pub fn main() -> Result<(), Error> {

    env_logger::init();

    let args = SyMCTSArgs::parse();
    let pid = std::process::id();

    #[cfg(not(feature="mutation_mode_fuzzing"))]
    log::info!("Running in {:?} concolic execution mode.", &args.concolic_execution_mode);
    #[cfg(not(feature="mutation_mode_fuzzing"))]
    match (&args.concolic_execution_mode, &args.symcc_target, &args.symqemu, &args.vanilla_target) {
        (ConcolicExecutionMode::SymCC, Some(_), _, _) => {},
        (ConcolicExecutionMode::SymQEMU, _, Some(_), Some(_)) => {},
        _ => {
            eprintln!("Invalid combination of concolic execution mode and target binaries.");
            eprintln!("If using symcc, specify a symcc target binary.");
            eprintln!("If using symqemu, specify a vanilla target binary and a symqemu binary.");
            eprintln!("Args: {:#?}", args);
            exit(1);
        }
    }

    let sync_dir = args.sync_dir.clone();
    let name = args.name.clone().unwrap_or_else(|| format!("symcts_{}", pid));
    let my_sync_dir = sync_dir.join(name.clone());
    std::fs::create_dir_all(&my_sync_dir).unwrap();
    let my_sync_dir_absolute = std::fs::canonicalize(&my_sync_dir).unwrap();

    let symcts_env_extras_cov = std::env::vars().filter_map(|(key, value)| {
        if key.starts_with("SYMCTS_ENV_COV_") {
            Some((key.to_owned().strip_prefix("SYMCTS_ENV_COV_").unwrap().to_owned(), value))
        } else {
            None
        }
    }).collect::<Vec<_>>();
    let symcts_env_extras_symcc = std::env::vars().filter_map(|(key, value)| {
        if key.starts_with("SYMCTS_ENV_SYMCC_") {
            Some((key.to_owned().strip_prefix("SYMCTS_ENV_SYMCC_").unwrap().to_owned(), value))
        } else {
            None
        }
    }).collect::<Vec<_>>();

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

    #[cfg(feature = "dhat-heap")]
    {
        let profile_dir = my_sync_dir.clone();
        let file_name = profile_dir.join(format!("heap-{}-0.json", pid));
        let mut _profiler = dhat::Profiler::builder().file_name(&file_name).build();

        let mut signals = Signals::new(&[SIGUSR1, SIGUSR2])?;

        thread::spawn(move || {

            let mut num_times_dumped = 1;
            for sig in signals.forever() {
                println!("SIGUSR received, dumping heap profile: {:?}", sig);
                drop(_profiler);
                println!("Heap profile dumped");
                _profiler = dhat::Profiler::builder()
                    .file_name(&profile_dir.join(format!("heap-{}-{}.json", pid, num_times_dumped)))
                    .build();
                num_times_dumped += 1;
            }
        });
    }


    let crashes_dir = my_sync_dir.join("crashes");
    let corpus_dir = my_sync_dir.join("queue");

    // 'While the stats are state, they are usually used in the broker - which is likely never restarted
    let monitor = MultiMonitor::new(|s| println!("{}", s));

    let (state, mut manager) = setup_restarting_mgr_std(
        monitor,
        args.broker_port,
        libafl::prelude::EventConfig::FromName { name_hash: hash_bytes(name.as_bytes()) },
    )?;
    println!("Restarting manager started: {:?}, {:?}", state, manager);
    manager.add_custom_buf_handler(Box::new(|state: &mut StdState<_, _, _, _>, tag, buf| {
        log::info!("Custom buf handler called with tag: {:?}, buf: {:?}", tag, buf);

        Ok(handle_concolic_execution_event(state, tag, buf))
    }));


    let time_coverage = TimeObserver::new("time_coverage");
    let time_concolic = TimeObserver::new("time_concolic");

    let mut shmem_provider = StdShMemProvider::new().unwrap();
    const MAP_SIZE: usize = 65536 * 16;
    std::env::set_var("AFL_MAP_SIZE", MAP_SIZE.to_string());
    let mut afl_shm = shmem_provider.new_shmem(MAP_SIZE).unwrap();
    afl_shm.write_to_env("__AFL_SHM_ID").unwrap();
    let afl_shm_id = afl_shm.id().to_string();

    let concolic_shm = shmem_provider
        .new_shmem(DEFAULT_SIZE)
        .unwrap();
    concolic_shm.write_to_env(DEFAULT_ENV_NAME).unwrap();


    #[cfg(not(feature="mutation_mode_fuzzing"))]
    let (concolic_observer_name, concolic_executor) = {
        let concolic_observer =
            ConcolicObserver::new("concolic".to_string(), concolic_shm.as_slice());

        let concolic_observer_name = concolic_observer.name().to_string();
        let concolic_executor =
            SymCCTracerCommandConfigurator::new(
                args.clone(),
                my_sync_dir.clone(),
                true,
                symcts_env_extras_symcc
            )
            .into_executor(tuple_list!(time_concolic, concolic_observer));

        (concolic_observer_name, concolic_executor)
    };

    let (mut feedback, mut cov_executor) = {

        // The concolic observer observers the concolic shared memory map.
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
            .build_dynamic_map(afl_map_observer, tuple_list!(time_coverage))?;

        log::debug!("Coverage executor: {:?}", coverage_executor);

        let coverage_executor = TimeoutForkserverExecutor::new(coverage_executor, Duration::from_millis(1000))?;

        (symcts_feedback, coverage_executor)
    };

    // A feedback to choose if an input is a solution or not
    let mut objective = CrashFeedback::new();

    // A minimization+queue policy to get testcasess from the corpus
    let symcts_scheduler = SyMCTSScheduler::new();

    // If not restarting, create a State from scratch
    let mut state = state.unwrap_or_else(||
        StdState::new(
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
        ).unwrap());

    let mut global_meta = SyMCTSGlobalMetadata::default();
    global_meta.sync_dir = my_sync_dir.clone();
    state.add_metadata(global_meta);
    state.add_metadata(SymbolicSolveStats::default());

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

    #[cfg(not(feature="mutation_mode_fuzzing"))]
    let mut stages = tuple_list!(
        // Create a concolic trace
        ConcolicTracingStage::new(TracingStage::new(concolic_executor), concolic_observer_name),
        // // Use the concolic trace for z3-based solving
        SyMCTSMutationalStage::new(),

        // #[cfg(feature="sync_from_other_fuzzers")]
        // SyncFromAFLStage::with_from_file(sync_dir),
    );
    #[cfg(feature="mutation_mode_fuzzing")]
    let mut stages = tuple_list!(
        StdMutationalStage::new(StdScheduledMutator::new(havoc_mutations())),
    );

    if !args.dry_run {
        #[cfg(feature = "fuzz_oneshot")]
        fuzzer.fuzz_one(
            &mut stages,
            &mut cov_executor,
            &mut state,
            &mut manager,
        )?;
        #[cfg(not(feature = "fuzz_oneshot"))]
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

    // manager.maybe_report_progress(&mut state, Duration::from_secs(1))?;
    #[cfg(feature="debug_symcts")]
    {
        let global_meta = state.metadata::<SyMCTSGlobalMetadata>().unwrap();
        let stats = state.metadata::<SymbolicSolveStats>().unwrap();
        let debug_dir = global_meta.sync_dir.join(".debug_symcts");
        std::fs::create_dir_all(&debug_dir).unwrap();
        let mut f = std::fs::File::create(debug_dir.join("final_global_meta.json")).unwrap();
        serde_json::to_writer_pretty(&mut f, &global_meta).unwrap();
        let mut f = std::fs::File::create(debug_dir.join("final_stats.json")).unwrap();
        serde_json::to_writer_pretty(&mut f, &stats).unwrap();
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

    // then dump the target SymCC binary (first field in the target_commandline) and the coverage-instrumented binary
    if let Some(symcc_target) = &args.symcc_target {
        if symcc_target.exists() {
            dump_binary_and_deps(&bin_dir.join("symcc_bin"), symcc_target);
        }
    }
    if let Some(qemu_path) = &args.symqemu {
        if qemu_path.exists() {
            dump_binary_and_deps(&bin_dir.join("symqemu"), qemu_path);
        }
    }
    if let Some(vanilla_path) = &args.vanilla_target {
        if vanilla_path.exists() {
            dump_binary_and_deps(&bin_dir.join("vanilla_bin"), vanilla_path);
        }
    }
}


#[cfg(not(feature="mutation_mode_fuzzing"))]
#[derive(Debug)]
pub struct SymCCTracerCommandConfigurator {
    symcts_args: SyMCTSArgs,
    my_sync_dir: PathBuf,
    extra_env: Vec<(String, String)>,
    _with_symbolic_input: bool,
}

#[cfg(not(feature="mutation_mode_fuzzing"))]
impl SymCCTracerCommandConfigurator {
    pub fn new(symcts_args: SyMCTSArgs, my_sync_dir: PathBuf, with_symbolic_input: bool, extra_env: Vec<(String, String)>) -> Self {
        SymCCTracerCommandConfigurator {
            symcts_args,
            my_sync_dir,
            extra_env,
            _with_symbolic_input: with_symbolic_input
        }
    }
}

#[cfg(not(feature="mutation_mode_fuzzing"))]
impl CommandConfigurator for SymCCTracerCommandConfigurator {
    fn spawn_child<I: Input + HasTargetBytes>(&mut self, input: &I) -> Result<Child, Error> {
        let args = &self.symcts_args.target_args;
        let file_input_path = self.my_sync_dir.join(".cur_input");
        let mut stdin = true;
        let mut cmd = match (self.symcts_args.concolic_execution_mode, &self.symcts_args.symcc_target, &self.symcts_args.symqemu, &self.symcts_args.vanilla_target) {
            (ConcolicExecutionMode::SymCC, Some(symcc_target), _, _) => Command::new(symcc_target),
            (ConcolicExecutionMode::SymQEMU, _, Some(symqemu_bin), Some(vanilla_target)) => {
                let mut cmd = Command::new(symqemu_bin);
                cmd.arg(vanilla_target);
                cmd
            },
            _ => panic!("Invalid combination of concolic execution mode and target binaries! Got mode {:?}, symcc-target {:?}, vanilla-target {:?}", self.symcts_args.concolic_execution_mode, self.symcts_args.symcc_target, self.symcts_args.vanilla_target),
        };
        cmd
            .stdin(Stdio::piped())
            .stdout(if std::env::var("SYMCTS_INHERIT_STDOUT").is_ok()
            {
                Stdio::inherit()
            } else {
                Stdio::null()
            })
            .stderr(if std::env::var("SYMCTS_INHERIT_STDERR").is_ok()
            {
                Stdio::inherit()
            } else {
                Stdio::null()
            });

        for arg in args {
            if arg == "@@" {
                assert!(stdin, "Multiple @@ arguments are not supported");
                stdin = false;
                cmd.arg(file_input_path.to_str().unwrap());
            }
            else {
                cmd.arg(arg);
            }
        }

        if !stdin {

            input.to_file(&file_input_path)?;
            cmd.env("SYMCC_INPUT_FILE", file_input_path);
        }
        cmd.env("SYMCC_TRACE_OUTPUT", "shmem");

        cmd.envs(self.extra_env.iter().map(|(k, v)| (k.as_str(), v.as_str())));

        log::debug!("Spawning child process: {:?}", cmd);
        let child = cmd.spawn().expect("Failed to spawn child process");
        if stdin {
            let mut stdin = child.stdin.as_ref().unwrap();
            if let Err(e) = stdin.write_all(input.target_bytes().as_slice()) {
                log::error!("Failed to write to stdin of child process: {}", e);
                // log the input to a file in .debug_symcts
                let debug_dir = self.my_sync_dir.join(".debug_symcts").join(".symcc_broken_pipe_probably");
                std::fs::create_dir_all(&debug_dir).unwrap();
                let hash = hash_bytes(input.target_bytes().as_slice());
                std::fs::File::create(
                    debug_dir.join(format!("input_{}.bin", hash)))
                    .expect("Failed to create file for symcc broken pipe input")
                    .write_all(input.target_bytes().as_slice())
                    .expect("Failed to write symcc crashing input to file");
                std::fs::File::create(
                    debug_dir.join(format!("input_{}.error", hash)))
                    .expect("Failed to create file for symcc broken pipe error")
                    .write_all(format!("Failed to write to stdin of child process: {}", e).as_bytes())
                    .expect("Failed to write symcc crashing error to file")

            }
        }
        Ok(child)
    }
    fn exec_timeout(&self) -> Duration {
        Duration::from_secs(3)
    }
}
