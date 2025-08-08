//! Execute the `fuzz` command

use anyhow::{ensure, Context, Result};

use std::collections::VecDeque;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::cmp::max;
use std::fs;
use std::collections::HashSet;
use std::hash::{DefaultHasher,Hasher,Hash};
use itertools::Itertools;

use core_affinity::CoreId;
use kvm_bindings::CpuId;
use kvm_ioctls::VmFd;

use crate::cmdline;
use crate::cmdline::ProjectCoverage;

use crate::config::Config;
use crate::coverage_analysis::CoverageAnalysis;
use crate::enable_manual_dirty_log_protect;
use crate::fuzz_input::{FuzzInput, FuzzHash, InputMetadata};
use crate::fuzzer::Fuzzer;
use crate::fuzzvm::FuzzVm;
use crate::rng::Rng;
use crate::stats::{self, PerfMark};
use crate::try_u64;
use crate::utils::{get_kcov_string, save_input_in_dir, save_input_in_dir_cov, write_coverage_in_dir};
use crate::{block_sigalrm, kick_cores, Stats, FINISHED};

use crate::{fuzzvm, unblock_sigalrm, write_crash_input_cov,write_crash_input, THREAD_IDS};
use crate::{handle_vmexit, init_environment, KvmEnvironment, ProjectState};
use crate::{memory, Cr3, Execution, ResetBreakpointType, Symbol, VbCpu, VirtAddr};

#[cfg(feature = "redqueen")]
use x86_64::registers::rflags::RFlags;

#[cfg(feature = "redqueen")]
use crate::cmp_analysis::RedqueenRule;

use crate::stack_unwinder::StackUnwinders;

/// DEBUGGING ONLY: Enable single step for all cores when fuzzing to debug what is happening during fuzzing
///
/// During testing, sometimes a crash was written to disk that did not reproduce in the
/// single step trace. This flag enables writing a single step trace of any crash found.
/// Since this enables single step for all fuzzing cores, it drastically reduces
/// performance of the fuzzing and should only be used for testing.
const SINGLE_STEP: bool = false;

/// Single step debugging enabled for all cores
pub static SINGLE_STEP_DEBUG: AtomicBool = AtomicBool::new(false);

/// Execute the fuzz subcommand to fuzz the given project
pub(crate) fn run<FUZZER: Fuzzer + 'static>(
    project_state: ProjectState,
    args: &cmdline::Fuzz,
) -> Result<()> {
    log::info!("{:x?}", project_state.config);

    let KvmEnvironment {
        kvm,
        cpuids,
        physmem_file,
        clean_snapshot_addr,
        symbols,
        symbol_breakpoints,
    } = init_environment(&project_state)?;

    // Get the number of cores to fuzz with
    let mut cores = args.cores.unwrap_or(1);
    if cores < 0 {
        if let Some(core_ids) = core_affinity::get_core_ids() {
            cores += core_ids.len() as i64;
        } else {
            log::warn!("Unable to get core ids. Defaulting to 1 core");
            cores = 1;
        }
    }

    if cores < 0 {
        log::warn!("No cores given. Defaulting to 1 core");
        cores = 1;
    }

    // Init list of all cores executing
    let mut threads = Vec::new();

    // Create a `Stats` for each core
    let stats: Vec<Arc<Mutex<Stats<FUZZER>>>> = (1..=cores)
        .map(|_| Arc::new(Mutex::new(Stats::default())))
        .collect();

    // Wrap the stats vec to pass to the CtrlC handler
    let stats = Arc::new(stats);

    // Get the first core to keep the main thread on
    let core_ids = core_affinity::get_core_ids().unwrap();
    let first_core = core_ids[0];

    // Create the directory to write crash files into if it doesn't exist
    let mut crash_dir = project_state.path.clone();
    crash_dir.push("crashes");
    if !crash_dir.exists() {
        std::fs::create_dir_all(&crash_dir).context("Failed to create crash dir")?;
    }

    log::warn!("Starting all {} worker threads", cores);

    // Read the input corpus from the given input directory
    let mut input_corpus = Vec::new();

    // Use the user given input directory or default to <PROJECT_DIR>/input
    let input_dir = if let Some(input_dir) = &args.input_dir {
        input_dir.clone()
    } else if project_state.path.join("current_corpus").exists() {
        // If no input dir was given, and the current corpus exists, use the old corpus
        project_state.path.join("current_corpus")
    } else {
        // Default to using the `input` directory
        project_state.path.join("input")
    };

    // Create a folder in /shared of the machine for seed synchnorizaton
    let output_dir = if let Some(output_dir) = &args.output_dir {
        String::from(output_dir.as_os_str().to_str().unwrap())
    } else {
        String::from(project_state.path.join("crashes").as_os_str().to_str().unwrap())
    };

    let jobid = &args.job_id.clone().unwrap();
    let syncdir_corpus_path = format!("{}/corpus-{}", output_dir, &jobid);
    match fs::create_dir_all(&syncdir_corpus_path) {
        Ok(_) => log::info!("Created directory: {:?}", syncdir_corpus_path),
        Err(e) => log::error!("Failed to create directory: {:?} with error: {:?}", syncdir_corpus_path, e),
    }

    let corpus_dir = format!("{}/benign_corpus", syncdir_corpus_path);
    let benign_coverage_dir = format!("{}/benign_coverage", syncdir_corpus_path);

    let crash_dir = format!("{}/crash_corpus", syncdir_corpus_path);
    let crash_coverage_dir = format!("{}/crash_coverage", syncdir_corpus_path);

    //print benign_coverage_dir as string
    log::warn!("benign_coverage_dir: {:?}", benign_coverage_dir);
    log::warn!("crash_coverage_dir: {:?}", crash_coverage_dir);

    let mut kcov_filter: Vec<u64> = Vec::<u64>::new();
    if let Some(kcov_filter_file) = &args.kcov_filter {
        let module_data = std::fs::read_to_string(kcov_filter_file)?;
        for line in module_data.split('\n') {
            // Ignore empty lines
            if line.is_empty() {
                continue;
            }
            let addr = u64::from_str_radix(&line.replace("0x", ""), 16).expect("Could not parse kcov filter line");

            if addr != 0x0 {
                kcov_filter.push(addr);
            }
        }
    }
    // kcov_filter.sort_by(|a, b | a.0.cmp(&b.0));

    let mut syscall_sequence: Vec<(u64, u64)> = Vec::new();
    if let Some(syscall_sequence_file) = &args.syscall_sequence {
        let module_data = std::fs::read_to_string(syscall_sequence_file)?;
        for line in module_data.split('\n') {
            // Ignore empty lines
            if line.is_empty() {
                continue;
            }
            let mut split = line.split(',');
            let addr_start = split.next().unwrap();
            let addr_end = split.next().unwrap();
            let addr1 = u64::from_str_radix(&addr_start.replace("0x", ""), 16).expect("Could not parse kcov filter line");
            let addr2 = u64::from_str_radix(&addr_end.replace("0x", ""), 16).expect("Could not parse kcov filter line");

            if addr1 != 0x0 && addr2 != 0x0 {
                syscall_sequence.push((addr1, addr2));
            }
        }
    }

    if input_dir.exists() {
        for file in input_dir.read_dir()? {
            let filepath = file?.path();

            // Ignore directories if they exist
            if filepath.is_dir() {
                log::debug!("Ignoring directory found in input dir: {:?}", filepath);
                continue;
            }

            input_corpus.push(FUZZER::Input::from_bytes(&std::fs::read(filepath)?)?);
        }
    } else {
        log::warn!("No input directory found: {input_dir:?}, starting with an empty corpus!");
    }
    // Get the corpus dir
    let path_corpus_dir = PathBuf::from(corpus_dir.clone());
    if !path_corpus_dir.exists() {
        std::fs::create_dir_all(&path_corpus_dir).context("Failed to create crash dir")?;
    }
    let path_crash_dir = PathBuf::from(crash_dir.clone());
    if !path_crash_dir.exists() {
        std::fs::create_dir_all(&path_crash_dir).context("Failed to create crash dir")?;
    }
    // Create crash and benign coverage directories if they don't exist
    let path_crash_coverage_dir = PathBuf::from(crash_coverage_dir.clone());
    if !path_crash_coverage_dir.exists() {
        std::fs::create_dir_all(&path_crash_coverage_dir).context("Failed to create crash coverage dir")?;
    }
    let path_bening_coverage_dir = PathBuf::from(benign_coverage_dir.clone());
    if !path_bening_coverage_dir.exists() {
        std::fs::create_dir_all(&path_bening_coverage_dir).context("Failed to create benign coverage dir")?;
    }
    // Initialize the dictionary
    let mut dict = None;
    let dict_dir = project_state.path.join("dict");
    if dict_dir.exists() {
        let mut new_dict = Vec::new();

        for file in std::fs::read_dir(dict_dir)? {
            let file = file?;
            new_dict.push(std::fs::read(file.path())?);
        }

        dict = Some(new_dict);
    } else {
        log::warn!("No dictionary in use. {dict_dir:?} not found.");
    }

    // Start each core with the full corpus
    let input_corpus_len = input_corpus.len();
    let starting_corp_len = input_corpus_len;
    let mut corp_counter = 0;

    log::info!(
        "Starting corpus: Total {} Per core {}",
        input_corpus_len,
        starting_corp_len
    );

    // Set the fuzz vm timeout
    let vm_timeout = args.timeout;

    log::info!("Execution timeout: {:?}", vm_timeout);

    let physmem_file_fd = physmem_file.as_raw_fd();

    // Get the coverage breakpoints for this core
    let ProjectCoverage {
        coverage_left,
        prev_coverage,
        prev_redqueen_coverage,
    } = project_state.coverage_left()?;

    log::info!("Coverage left: {}", coverage_left.len());

    let mut starting_corp = Vec::new();

    // Add the new corpus to the core
    for _ in 0..starting_corp_len {
        starting_corp.push(input_corpus[corp_counter].clone());
        corp_counter = (corp_counter + 1) % input_corpus_len;
    }

    // Add a single input if none found
    if starting_corp.is_empty() {
        let mut rng = Rng::new();
        let input = FUZZER::Input::generate(&[], &mut rng, &dict, FUZZER::MAX_INPUT_LENGTH);
        starting_corp.push(input.clone());
        input_corpus.push(input);
    }

    // Init the coverage breakpoints mapping to byte
    let mut covbp_bytes = BTreeMap::new();

    // Start timer for writing all coverage breakpoints
    let start = Instant::now();

    // Write the remaining coverage breakpoints into the "clean" snapshot
    let mut mem = memory::Memory::from_addr(clean_snapshot_addr);
    let mut count = 0;
    let cr3 = Cr3(project_state.vbcpu.cr3);
    for addr in &coverage_left {
        if let Ok(orig_byte) = mem.read::<u8>(*addr, cr3) {
            //mem.write_bytes(*addr, cr3, &[0xcc])?;
            //covbp_bytes.insert(*addr, orig_byte);
            //count += 1;
        }
    }

    log::info!("Pre-populating coverage breakpoints");
    log::info!(
        "Given {:?} | Valid {:?} | Can write {:16.2} covbps/sec",
        coverage_left.len(),
        covbp_bytes.len(),
        f64::from(count) / start.elapsed().as_secs_f64()
    );

    #[cfg(feature = "redqueen")]
    let redqueen_rules: BTreeMap<u64, BTreeSet<RedqueenRule>> = BTreeMap::new();

    /*
    let redqueen_rules_path = project_state.path.join("redqueen.rules");
    let redqueen_rules_bytes = std::fs::read(&redqueen_rules_path).unwrap_or_default();
    if !redqueen_rules_bytes.is_empty() {
        redqueen_rules = serde_json::from_slice(&redqueen_rules_bytes)?;
    }
    log::info!("Redqueen rules: {}", redqueen_rules.len());
    */

    // Due to the time it takes to clone large corpi, symbols, or coverage breakpoints,
    // we bulk clone as many as we need for all the cores at once and then `.take` them
    // from these collections
    let start = std::time::Instant::now();
    log::info!(
        "Cloning corpus of {} for {} cores",
        starting_corp.len(),
        cores
    );
    let mut starting_corps = (0..=cores)
        .map(|_| starting_corp.clone())
        .collect::<Vec<_>>();
    log::info!("...took {:?}", start.elapsed());

    let start = std::time::Instant::now();
    let mut starting_symbols = (0..=cores).map(|_| symbols.clone()).collect::<Vec<_>>();
    log::info!("Cloned {} symbols in {:?}", cores, start.elapsed());

    let start = std::time::Instant::now();
    let mut starting_covbps = (0..=cores).map(|_| covbp_bytes.clone()).collect::<Vec<_>>();
    log::info!("Cloned {} covbps in {:?}", cores, start.elapsed());

    let start = std::time::Instant::now();
    let mut starting_dicts = (0..=cores).map(|_| dict.clone()).collect::<Vec<_>>();
    log::info!("Cloned {} dictionaries in {:?}", cores, start.elapsed());

    let start = std::time::Instant::now();
    let mut starting_configs = (0..=cores)
        .map(|_| project_state.config.clone())
        .collect::<Vec<_>>();
    log::info!("Cloned {} configs in {:?}", cores, start.elapsed());

    let start = std::time::Instant::now();
    let mut starting_unwinders = (0..=cores)
        .map(|_| project_state.unwinders.clone())
        .collect::<Vec<_>>();
    log::info!("Cloned {} unwinders in {:?}", cores, start.elapsed());

    let start = std::time::Instant::now();
    let mut starting_prev_coverage = (0..=cores)
        .map(|_| prev_coverage.clone())
        .collect::<Vec<_>>();
    log::info!(
        "Cloned {} previous coverage in {:?}",
        cores,
        start.elapsed()
    );

    let start = std::time::Instant::now();
    let mut starting_kcov_filter = (0..=cores)
        .map(|_| kcov_filter.clone())
        .collect::<Vec<_>>();
    log::info!(
        "Clone {} kcov filters in {:?}",
        cores,
        start.elapsed()
    );

    let start = std::time::Instant::now();
    let mut starting_syscall_sequence = (0..=cores)
        .map(|_| syscall_sequence.clone())
        .collect::<Vec<_>>();
    log::info!(
        "Clone {} syscall sequence in {:?}",
        cores,
        start.elapsed()
    );

    let start = std::time::Instant::now();
    let mut starting_crash_dir = (0..=cores)
        .map(|_| crash_dir.clone())
        .collect::<Vec<_>>();
    log::info!(
        "Cloned {} output_dir in {:?}",
        cores,
        start.elapsed()
    );

    let start = std::time::Instant::now();
    let mut starting_corpus_dir = (0..=cores)
        .map(|_| corpus_dir.clone())
        .collect::<Vec<_>>();
    log::info!(
        "Cloned {} corpus_dir in {:?}",
        cores,
        start.elapsed()
    );

    #[cfg(feature = "redqueen")]
    let mut starting_prev_redqueen_coverage = {
        let start = std::time::Instant::now();
        let result = (0..=cores)
            .map(|_| prev_redqueen_coverage.clone())
            .collect::<Vec<_>>();
        log::info!(
            "Cloned {} previous redqueen coverage in {:?}",
            cores,
            start.elapsed()
        );
        result
    };

    #[cfg(feature = "redqueen")]
    let mut starting_redqueen_rules = {
        let start = std::time::Instant::now();
        let result = (0..=cores)
            .map(|_| redqueen_rules.clone())
            .collect::<Vec<_>>();
        log::info!("Cloned {} redqueen rules in {:?}", cores, start.elapsed());
        result
    };

    let start = std::time::Instant::now();
    let mut starting_sym_breakpoints = (0..=cores)
        .map(|_| symbol_breakpoints.clone())
        .collect::<Vec<_>>();
    log::info!(
        "Cloned {} symbol breakpoints in {:?}",
        cores,
        start.elapsed()
    );

    let enable_lapic = args.enable_lapic;

    // Create a thread for each active CPU core.
    for id in 1..=cores {
        let core_id = CoreId {
            id: usize::try_from(id)?,
        };

        // Create the VM for this core
        let mut retries = 0;
        let vm = loop {
            retries += 1;
            if let Ok(vm) = kvm.create_vm() {
                break vm
            } else {
                log::error!("Failed to create VM from KVM, retrying... {retries}/4");
            }
            if retries == 4 {
                panic!("Failed to create VM from KVM after reaching max retries");
            }
        };

        // Enable dirty bits
        enable_manual_dirty_log_protect(&vm)?;

        // Copy the CPUIDs for this core
        let cpuids = cpuids.clone();

        // Get core local copies of the symbols and crashing symbols
        let id: usize = id.try_into().unwrap();

        // Get the stats for this core
        let core_stats = stats[core_id.id - 1].clone();

        // Get the starting resources for this specific core
        let curr_symbols = std::mem::take(&mut starting_symbols[id]);
        let corpus = std::mem::take(&mut starting_corps[id]);
        let symbol_breakpoints = std::mem::take(&mut starting_sym_breakpoints[id]);
        let coverage_breakpoints = Some(std::mem::take(&mut starting_covbps[id]));
        let dictionary = std::mem::take(&mut starting_dicts[id]);
        let prev_coverage = std::mem::take(&mut starting_prev_coverage[id]);
        let kcov_filter = Some(std::mem::take(&mut starting_kcov_filter[id]));
        let syscall_sequence = Some(std::mem::take(&mut starting_syscall_sequence[id]));
        let crash_dir = Some(std::mem::take(&mut starting_crash_dir[id]));
        let corpus_dir = Some(std::mem::take(&mut starting_corpus_dir[id]));
        let config = std::mem::take(&mut starting_configs[id]);
        let crash_coverage_dir = Some(crash_coverage_dir.clone());
        let benign_coverage_dir = Some(benign_coverage_dir.clone());
        let unwinders = std::mem::take(&mut starting_unwinders[id]);

        #[cfg(feature = "redqueen")]
        let prev_redqueen_coverage = std::mem::take(&mut starting_prev_redqueen_coverage[id]);

        #[cfg(feature = "redqueen")]
        let redqueen_rules = std::mem::take(&mut starting_redqueen_rules[id]);

        // Get an owned copy of the crash dir for this core
        let project_dir = project_state.path.clone();

        if id % 5 == 0 {
            println!("Starting core: {}/{}", core_id.id, cores);
        }

        let vbcpu = project_state.vbcpu.clone();

        // Start executing on this core
        let thread = std::thread::spawn(move || -> Result<()> {
            let result = std::panic::catch_unwind(|| -> Result<()> {
                start_core::<FUZZER>(
                    core_id,
                    &vm,
                    &vbcpu,
                    &cpuids,
                    physmem_file_fd,
                    clean_snapshot_addr,
                    &curr_symbols,
                    symbol_breakpoints,
                    coverage_breakpoints,
                    &core_stats,
                    &project_dir,
                    vm_timeout,
                    corpus,
                    &dictionary,
                    prev_coverage,
                    &config,
                    unwinders,
                    kcov_filter,
                    syscall_sequence,
                    crash_dir,
                    corpus_dir,
                    benign_coverage_dir,
                    crash_coverage_dir,
                    enable_lapic,
                    #[cfg(feature = "redqueen")]
                    prev_redqueen_coverage,
                    #[cfg(feature = "redqueen")]
                    redqueen_rules,
                    #[cfg(feature = "redqueen")]
                    project_state.redqueen_available,
                )
            });

            // Ensure this thread is signalling it is not alive
            core_stats.lock().unwrap().alive = false;

            match result {
                Ok(no_panic_result) => no_panic_result,
                Err(_panic_result) => {
                    // Convert the panic result into a string for printing
                    // while the other threads are shutting down
                    /*
                    let err_msg = panic_result.downcast::<String>().ok();
                    log::warn!("ERROR FROM CORE {id}: {err_msg:?}");
                    tui_logger::move_events();
                    println!("ERROR FROM CORE {id}: {err_msg:?}");
                    FINISHED.store(true, Ordering::SeqCst);
                    */

                    // If any thread panics, force all other threads to die
                    FINISHED.store(true, Ordering::SeqCst);

                    Ok(())
                }
            }
        });

        // Sleep to let the system catch up to the threads being created
        std::thread::sleep(std::time::Duration::from_millis(100));

        // Add this thread to the total list of threads
        threads.push(Some(thread));
    }

    // Collect all the threads
    // let mut results  = Vec::new();

    //  Setup the CTRL+C handler
    let ctrl_c_stats = stats.clone();
    let res = ctrlc::set_handler(move || {
        log::info!("CTRL C PRESSED!");

        // Signal cores to terminate
        for core_stats in ctrl_c_stats.iter() {
            core_stats.lock().unwrap().forced_shutdown = true;
            // core_stats.lock().unwrap().alive = false;
        }

        // Signal stats display to terminate
        FINISHED.store(true, Ordering::SeqCst);
    });

    if let Err(e) = res {
        log::warn!("Error setting CTRL+C hander: {e:}");
    }

    // Spawn the kick cores thread
    let kick_cores_thread = std::thread::spawn(move || {
        // Ignore the SIGALRM for this thread
        block_sigalrm().unwrap();

        // Set the core affinity for this core to always be 0

        // Start the kick cores worker
        kick_cores();
    });

    // The command line argument is set when asking for ASCII stats. Invert this
    // result to determine if we use TUI.
    let tui = !args.ascii_stats;

    let project_dir = project_state.path.clone();

    let mut cov_analysis = None;
    let mut cov_analysis_state = None;
    project_dir
        .read_dir()
        .expect("Failed to read project_dir")
        .for_each(|file| {
            if let Ok(file) = file {
                if let Some(extension) = file.path().extension() {
                    if extension.to_str() == Some("coverage_analysis") {
                        cov_analysis = Some(file);
                    } else if extension.to_str() == Some("coverage_analysis_state") {
                        cov_analysis_state = Some(file);
                    }
                }
            }
        });

    let mut coverage_analysis = None;

    if let Some(state_file) = cov_analysis_state {
        log::info!("Loading coverage analysis from state");
        coverage_analysis = Some(CoverageAnalysis::load_state(&state_file.path())?);
    } else if let Some(cov_file) = cov_analysis {
        log::info!("Loading coverage analysis from binary ninja file");
        let analysis = CoverageAnalysis::from_binary_ninja(&cov_file.path())?;
        let state_file = cov_file.path().with_extension("coverage_analysis_state");
        analysis.save_state(&state_file)?;

        coverage_analysis = Some(analysis);
    };

    // Spawn the stats thread if there isn't a single step trace happening
    let curr_stats = stats;
    let stats_thread = std::thread::spawn(move || {
        // Ignore the SIGALRM for this thread
        block_sigalrm().unwrap();

        // Set the core affinity for this core to always be 0

        // let prev_coverage = prev_coverage.iter().map(|x| x.0).collect();

        // Start the stats worker
        let res = stats::worker(
            curr_stats,
            &project_state.modules,
            &project_dir,
            prev_coverage,
            prev_redqueen_coverage,
            &input_corpus,
            project_state.coverage_breakpoints,
            &symbols,
            coverage_analysis,
            corpus_dir.into(),
            output_dir.into(),
            tui,
            &project_state.config,
            &benign_coverage_dir,
        );

        if let Err(e) = res {
            FINISHED.store(true, Ordering::SeqCst);
            eprintln!("{e:?}");
        }
    });

    let mut errors = Vec::new();

    'done: loop {
        let mut all_finished = true;

        #[allow(clippy::needless_range_loop)]
        for index in 0..threads.len() {
            if let Some(thread) = threads[index].take() {
                if thread.is_finished() {
                    match thread.join() {
                        Err(e) => {
                            FINISHED.store(true, Ordering::SeqCst);

                            errors.push(format!(
                                "Thread {index} panic: {:?}",
                                e.downcast::<String>()
                            ));
                            // errors.push(e);

                            /*
                            for stat in stats.iter() {
                                stat.lock().unwrap().alive = false;
                            }
                            */

                            break 'done;
                        }
                        Ok(Err(e)) => {
                            // Some thread exited with an error. Force all
                            // threads to also die
                            crate::stats_tui::restore_terminal()?;
                            FINISHED.store(true, Ordering::SeqCst);
                            println!("Thread {index} returned err.. {e:?}");
                        }
                        x => {
                            println!("Thread {index} returned success.. {x:?}");
                        }
                    }
                } else {
                    all_finished = false;
                    threads[index] = Some(thread);
                }
            }
        }

        if all_finished || FINISHED.load(Ordering::SeqCst) {
            break;
        }

        std::thread::sleep(std::time::Duration::from_millis(200));
    }

    println!("Stats thread: {:?}", stats_thread.join());
    println!("Kick thread: {:?}", kick_cores_thread.join());

    for error in errors {
        eprintln!("{error:?}");
    }

    Ok(())
}

/// Thread worker used to fuzz the given [`VbCpu`] state with the given physical memory.
fn start_core<FUZZER: Fuzzer>(
    core_id: CoreId,
    vm: &VmFd,
    vbcpu: &VbCpu,
    cpuid: &CpuId,
    snapshot_fd: i32,
    clean_snapshot: u64,
    symbols: &Option<VecDeque<Symbol>>,
    symbol_breakpoints: Option<BTreeMap<(VirtAddr, Cr3), ResetBreakpointType>>,
    coverage_breakpoints: Option<BTreeMap<VirtAddr, u8>>,
    core_stats: &Arc<Mutex<Stats<FUZZER>>>,
    project_dir: &Path,
    vm_timeout: Duration,
    mut corpus: Vec<FUZZER::Input>,
    dictionary: &Option<Vec<Vec<u8>>>,
    prev_coverage: BTreeSet<VirtAddr>,
    config: &Config,
    unwinders: StackUnwinders,
    kcov_filter: Option<Vec<u64>>,
    syscall_sequence: Option<Vec<(u64, u64)>>,
    output_dir: Option<String>,
    benign_dir: Option<String>,
    benign_cov_dir: Option<String>,
    crash_cov_dir: Option<String>,
    enable_lapic: bool,
    #[cfg(feature = "redqueen")] prev_redqueen_coverage: BTreeSet<(VirtAddr, RFlags)>,
    #[cfg(feature = "redqueen")] redqueen_rules: BTreeMap<u64, BTreeSet<RedqueenRule>>,
    #[cfg(feature = "redqueen")] redqueen_availble: bool,
) -> Result<()> {
    /// Helper macro to time the individual components of resetting the guest state
    macro_rules! time {
        ($marker:ident, $expr:expr) => {{
            // Init the timer
            core_stats
                .lock()
                .unwrap()
                .perf_stats
                .start(PerfMark::$marker);

            // Execute the given expression
            let result = $expr;

            // Calculate the time took to execute $expr
            core_stats
                .lock()
                .unwrap()
                .perf_stats
                .mark(PerfMark::$marker);

            // Return the result from the expression
            result
        }};
    }

    let crash_dir = PathBuf::from(output_dir.unwrap());
    let corpus_dir = PathBuf::from(benign_dir.unwrap());
    let benign_coverage_dir = PathBuf::from(benign_cov_dir.unwrap());
    let crash_coverage_dir = PathBuf::from(crash_cov_dir.unwrap());

    // Store the thread ID of this thread used for passing the SIGALRM to this thread
    let thread_id = unsafe { libc::pthread_self() };
    *THREAD_IDS[core_id.id].lock().unwrap() = Some(thread_id);

    // Set the core affinity for this core

    // Unblock SIGALRM to enable this thread to handle SIGALRM
    unblock_sigalrm()?;

    let mut fuzzer = FUZZER::default();

    // RNG for this core used for mutation of inputs
    let mut rng = Rng::new();

    // Sanity check that the given fuzzer matches the snapshot
    ensure!(
        FUZZER::START_ADDRESS == vbcpu.rip,
        fuzzvm::Error::SnapshotMismatch
    );

    // Create a 64-bit VM for fuzzing
    let mut fuzzvm = FuzzVm::create(
        u64::try_from(core_id.id)?,
        &mut fuzzer,
        vm,
        vbcpu,
        cpuid,
        snapshot_fd.as_raw_fd(),
        clean_snapshot,
        coverage_breakpoints,
        symbol_breakpoints,
        symbols,
        config.clone(),
        unwinders,
        enable_lapic,
        #[cfg(feature = "redqueen")]
        redqueen_rules,
    )?;

    let mut syscall_addr_sequence = Vec::<(u64, u64)>::new();
    if let Some(syscall_sequence) = syscall_sequence {
        syscall_addr_sequence = syscall_sequence;
    }
    let mut syscall_sequence_score = 0;

    let mut coverage = prev_coverage;
    let mut kcov: HashSet<u64>;
    #[cfg(feature = "redqueen")]
    let mut redqueen_coverage = prev_redqueen_coverage;

    // Addresses covered by the current input
    let mut new_coverage_for_input = BTreeSet::new();
    // TODO:
    // kcov_bitmap and kcov_bitmap_for_input
    // A dictionary mapping addresses within the ranges of the kcov_filters
    // To 8 bit values that represent the hit counts of the edges
    let mut core_kcov_cov: HashSet<VirtAddr> = HashSet::<VirtAddr>::new();
    //let mut inputs_kcov_cov = Vec::<(BTreeSet<VirtAddr>,<FUZZER as Fuzzer>::Input,u64)>::new();
    let mut core_sync_corpus_set: Vec<(<FUZZER as Fuzzer>::Input,u64,String)> = Vec::new();

    let mut sanitizer_bitmap: Vec<u8> = Vec::<u8>::new();
    let mut sanitizer_bitmap_for_input: Vec<u8>;

    // Number of iterations before syncing stats
    let mut last_sync = std::time::Instant::now();
    let mut last_corpus_sync = std::time::Instant::now();

    // Start the performance counter for the total elapsed time
    core_stats.lock().unwrap().perf_stats.start(PerfMark::Total);

    let mut iters = 0;

    // Sanity warn that all cores are in single step when debugging
    if SINGLE_STEP && SINGLE_STEP_DEBUG.load(Ordering::SeqCst) && core_id.id == 1 {
        log::warn!("SINGLE STEP FUZZING ENABLED");
        log::warn!("SINGLE STEP FUZZING ENABLED");
        log::warn!("SINGLE STEP FUZZING ENABLED");
        fuzzvm.enable_single_step()?;
    }

    'finish: for _iter in 0.. {
        // Signal that this core is alive
        core_stats.lock().unwrap().alive = true;

        // Mark and reset the performance counter for the total elapsed time
        core_stats.lock().unwrap().perf_stats.mark(PerfMark::Total);
        core_stats.lock().unwrap().perf_stats.start(PerfMark::Total);

        // Sync the corpus with the main stats
        if last_corpus_sync.elapsed() >= config.stats.merge_coverage_timer {
            // Replace the fuzzer corpus
            let mut curr_stats = core_stats.lock().unwrap();

            if let Some(new_corp) = curr_stats.new_corpus.take() {
                if !new_corp.is_empty() {
                    // Send the current corpus to the main corpus collection
                    curr_stats.old_corpus = Some(corpus);
                    curr_stats.old_corp = Some(core_sync_corpus_set.clone());
                    //curr_stats.old_corpus_cov = Some(inputs_kcov_cov.clone());
                    //inputs_kcov_cov.clear();
                    core_sync_corpus_set.clear();
                    corpus = new_corp;
                }
            }

            /*
            // Sync this core's redqueen rules with the main thread's rules
            if fuzzvm.core_id <= REDQUEEN_CORES {
                // Add this core's rules to the total rules from the main thread
                curr_stats.redqueen_rules.append(&mut fuzzvm.redqueen_rules);

                // Copy the newly updated main thread's stats to this core (effectively
                // syncing the rules with the core)
                fuzzvm.redqueen_rules = curr_stats.redqueen_rules.clone();
            }
            */

            // Reset the last corpus sync counter
            last_corpus_sync = Instant::now();
        }

        // Sync the current stats to the main stats after 500ms
        if last_sync.elapsed() >= Duration::from_millis(500) {
            time!(StatsSync, {
                // Add the current iterations to the coverage
                core_stats.lock().unwrap().iterations += iters;

                // Append the current coverage
                core_stats.lock().unwrap().coverage.append(&mut coverage);

                // Reset the local coverage to match the global coverage set in stats
                for addr in &core_stats.lock().unwrap().coverage {
                    coverage.insert(*addr);
                }

                // Reset the local coverage to match the global coverage set in stats
                /*
                core_stats.lock().unwrap().redqueen_coverage.append(&mut redqueen_coverage);
                for cov in &core_stats.lock().unwrap().redqueen_coverage {
                    redqueen_coverage.insert(*cov);
                }
                */

                // Update the number of remaining number of coverage breakpoints
                if let Some(ref cov_bps) = fuzzvm.coverage_breakpoints {
                    core_stats.lock().unwrap().cov_left = u32::try_from(cov_bps.len())?;
                }

                // Reset the iteration counter
                iters = 0;

                // Reset the last sync counter
                last_sync = Instant::now();
            });
        }

        iters += 1;

        // Reset new coverage marker
        new_coverage_for_input.clear();

        // Reset the fuzzer state
        fuzzer.reset_fuzzer_state();

        // Get a random input from the corpus
        let mut input = time!(
            ScheduleInput,
            fuzzer.schedule_next_input(&corpus, &mut rng, dictionary)
        );

        let original_file = input.fuzz_hash();

        let orig_corpus_len = corpus.len();
        let orig_coverage_len = coverage.len();

        // Gather redqueen for this input if there aren't already replacement rules found
        #[cfg(feature = "redqueen")]
        if redqueen_availble {
            time!(Redqueen, {
                // If this input has never been through redqueen or hit the small change to go through again,
                // execute redqueen on this input
                if fuzzvm.core_id <= config.redqueen.cores
                    && (!fuzzvm.redqueen_rules.contains_key(&input.fuzz_hash())
                        || (fuzzvm.rng.next() % 1000) == 42)
                {
                    let redqueen_time_spent = Duration::from_secs(0);

                    // Signal this thread is in redqueen
                    core_stats.lock().unwrap().in_redqueen = true;
                    core_stats.lock().unwrap().iterations = 0;

                    let orig_corpus_len = corpus.len();

                    // Execute redqueen for this input
                    fuzzvm.gather_redqueen(
                        &input,
                        &mut fuzzer,
                        vm_timeout,
                        &mut corpus,
                        &mut coverage,
                        &mut redqueen_coverage,
                        redqueen_time_spent,
                        &project_dir.join("metadata"),
                    )?;

                    // Signal this thread is in not in redqueen
                    core_stats.lock().unwrap().in_redqueen = false;

                    // If redqueen found new inputs, write them to disk
                    if corpus.len() > orig_corpus_len {
                        for input in &corpus {
                            save_input_in_dir(input, &corpus_dir)?;
                        }
                    }
                }
            });

            /*
            // Sanity check redqueen breakpoints are being overwritten
            for addr in FUZZER::redqueen_breakpoint_addresses() {
                if fuzzvm.read::<u8>(VirtAddr(*addr), fuzzvm.cr3())? == 0xcc {
                    log::info!("RQ addr still in place! {addr:#x}");
                    panic!();
                }
            }
            */
        }

        if corpus.len() != orig_corpus_len {
            log::info!("Redqueen new corpus! {orig_corpus_len} -> {}", corpus.len());
        }

        if coverage.len() != orig_coverage_len {
            log::info!(
                "Redqueen new coverage! {orig_coverage_len} -> {}",
                coverage.len()
            );
        }

        // Mutate the input based on the fuzzer
        let mutation = time!(
            InputMutate,
            fuzzer.mutate_input(&mut input, &corpus, &mut rng, dictionary)
        );

        // Set the input into the VM as per the fuzzer
        time!(InputSet, fuzzer.set_input(&input, &mut fuzzvm)?);

        let mut execution;

        let mut symbol = String::new();
        let mut instrs = Vec::new();
        let mut i = 0;

        // if SINGLE_STEP_DEBUG.load(Ordering::SeqCst) || fuzzvm.rng.next() % 2 == 0 {
        if SINGLE_STEP {
            if fuzzvm.rng.next() % 2 == 0 {
                SINGLE_STEP_DEBUG.store(true, Ordering::SeqCst);
                fuzzvm.enable_single_step()?;
            } else {
                SINGLE_STEP_DEBUG.store(false, Ordering::SeqCst);
                fuzzvm.disable_single_step()?;
            }
        }

        let mut perf = crate::fuzzvm::VmRunPerf::default();
        let mut interesting_kern_input = false;
        let mut interesting_syscall_input = false;
        // Top of the run iteration loop for the current fuzz case
        loop {
            if SINGLE_STEP && SINGLE_STEP_DEBUG.load(Ordering::SeqCst) {
                // Add the current instruction to the trace
                let rip = fuzzvm.regs().rip;
                let cr3 = fuzzvm.cr3();
                let instr = fuzzvm
                    .get_current_verbose_instruction_string()
                    .ok()
                    .unwrap_or_else(|| String::from("???"));

                // Get the symbol for RIP if we have a symbols database
                if let Some(ref sym_data) = symbols {
                    // Clear the re-used String allocation for the symbol
                    symbol.clear();

                    // Get the symbol itself
                    let curr_symbol = crate::symbols::get_symbol(rip, sym_data)
                        .unwrap_or_else(|| "UnknownSym".to_string());
                    symbol.push_str(&curr_symbol.to_string());
                }

                instrs.push(format!(
                    "INSTRUCTION {:07} {:#018x} {:#010x} | {:60}\n    {instr}",
                    i,
                    rip,
                    u64::try_from(cr3.0).unwrap(),
                    symbol
                ));

                i += 1;
            }

            // Execute the VM
            let ret = fuzzvm.run(&mut perf)?;

            // Add the performance counters to the stats from execution of the VM
            core_stats
                .lock()
                .unwrap()
                .perf_stats
                .add(PerfMark::InVm, perf.in_vm);
            core_stats
                .lock()
                .unwrap()
                .perf_stats
                .add(PerfMark::PreRunVm, perf.pre_run_vm);
            core_stats
                .lock()
                .unwrap()
                .perf_stats
                .add(PerfMark::PostRunVm, perf.post_run_vm);

            core_stats.lock().unwrap().inc_vmexit(&ret);

            // Get the RIP immediately after returning from run()
            let rip = VirtAddr(fuzzvm.rip());

            // Handle the FuzzVmExit to determine if the VM should continue or reset
            execution = time!(
                HandleVmExit,
                handle_vmexit(&ret, &mut fuzzvm, &mut fuzzer, Some(&crash_dir), &input)?
            );

            // log::info!("Total kcov addrs: {}", kcov_addrs.len());
            //match filter_flag {
            //    true => {
            //        kcov_bitmap_for_input = kcov_bitmap.keys().map(|&key| (key, 0)).collect();
            //        kcov_addrs
            //            .into_iter()
            //            .for_each(|addr| {
            //                kcov_bitmap_for_input.entry(addr).and_modify(|count| *count += 1);
            //            });
            //    },
            //    false => {
            //        kcov_bitmap_for_input = HashMap::<u64, u8>::new();
            //    }
            //};
            // log::info!("Final kcov bitmap: {}", kcov_bitmap_for_input.len());

            // If we hit a coverage execution, add the RIP to
            if matches!(execution, Execution::CoverageContinue) && coverage.insert(rip) {
                // log::info!("New cov: {rip:#x}");
                new_coverage_for_input.insert(rip);
            }

            // If we hit a coverage execution, add the RIP to
            if fuzzvm.single_step
                && fuzzvm
                    .coverage_breakpoints
                    .as_ref()
                    .unwrap()
                    .contains_key(&rip)
                && coverage.insert(rip)
            {
                // log::info!("New cov: {rip:#x}");
                new_coverage_for_input.insert(rip);
            }

            if SINGLE_STEP {
                // During single step, breakpoints aren't triggered. For this reason,
                // we need to check if the instruction is a breakpoint regardless in order to
                // apply fuzzer specific breakpoint logic. We can ignore the "unknown breakpoint"
                // error that is thrown if a breakpoint is not found;
                if let Ok(new_execution) = fuzzvm.handle_breakpoint(&mut fuzzer, &input) {
                    execution = new_execution;
                }
            }

            if fuzzvm.start_time.elapsed() > vm_timeout {
                execution = Execution::TimeoutReset;
            }

            match execution {
                Execution::Reset | Execution::CrashReset { .. } | Execution::TimeoutReset => {
                    // Reset the VM if requested
                    break;
                }
                Execution::Continue | Execution::CoverageContinue => {
                    // Nothing to do for continuing execution
                }
            }
        }

        let kcov_addrs = match fuzzer.get_kcov_coverage(&mut fuzzvm) {
            Ok(foo) => foo,
            Err(_) => Vec::<u64>::new()
        };
        // kcov = kcov_addrs.clone();

        // TODO: Check if we've hit the syscall sequence in the kcov addresses

        let mut syscall_sequence_score_for_input = 0;
        let mut syscall_sequence_hit_ctr = 0;
        for kcov_addr in kcov_addrs.iter() {
            // Check if the current kcov address is in the syscall sequence after index syscall_sequence_hit_ctr
            if syscall_addr_sequence.len() > 0 {
                if syscall_addr_sequence.len() > syscall_sequence_hit_ctr {
                    let remainder_sequence = &syscall_addr_sequence[syscall_sequence_hit_ctr..];
                    for (start_addr, end_addr) in remainder_sequence {
                        if kcov_addr >= start_addr && kcov_addr < end_addr {
                            log::debug!("Hit syscall sequence: {kcov_addr:#x}");
                            let idx = remainder_sequence.iter().position(|x| x.0 == *start_addr && x.1 == *end_addr).unwrap();
                            syscall_sequence_hit_ctr += idx + 1;
                            syscall_sequence_score_for_input += 1;
                            if idx == 0 {
                                syscall_sequence_score_for_input += 1;
                            }
                        }
                    }
                }
            }
            let kcov_addr = VirtAddr(*kcov_addr);
            if core_kcov_cov.insert(kcov_addr) {
                // new_coverage_for_input.insert(kcov_addr);
                interesting_kern_input = true;
            }
            // input_kcov_cov.insert(kcov_addr);
        }
        if syscall_sequence_score_for_input > syscall_sequence_score {
            syscall_sequence_score = syscall_sequence_score_for_input;
            log::info!("New syscall sequence score: {syscall_sequence_score_for_input}");
            interesting_syscall_input = true;
            interesting_kern_input = true;
        }
        sanitizer_bitmap_for_input = match fuzzer.get_sanitizer_coverage(&mut fuzzvm) {
            Ok(foo) => foo,
            Err(_) => Vec::<u8>::new()
        };
        // Exit the fuzz loop if told to
        // MUST BE IN THE RUN LOOP
        if core_stats.lock().unwrap().forced_shutdown || crate::FINISHED.load(Ordering::SeqCst) {
            break 'finish;
        }

        /*
        if SINGLE_STEP && SINGLE_STEP_DEBUG.load(Ordering::SeqCst) {
            std::fs::write(format!("/tmp/instrs_{}", instrs.len()), instrs.join("\n"));
        }
        */

        // If crashed, increase the crashes in the stats
        if matches!(execution, Execution::TimeoutReset) {
            // Increment the timeouts count
            core_stats.lock().unwrap().timeouts += 1;

            // time!(SaveTimeoutInput, {
            //     let mut input_bytes = Vec::new();
            //     input.to_bytes(&mut input_bytes)?;

            //     // Attempt to write the crashing input and pass to fuzzer if it is a new input
            //     if let Some(crash_file) =
            //         write_crash_input(&crash_dir, "timeout", &input_bytes, &fuzzvm.console_output)?
            //     {
            //         if SINGLE_STEP && SINGLE_STEP_DEBUG.load(Ordering::SeqCst) {
            //             std::fs::write(
            //                 crash_file.with_extension("single_step"),
            //                 instrs.join("\n"),
            //             )?;
            //         }

            //         // Allow the fuzzer to handle the crashing state
            //         // Useful for things like syscall fuzzer to write a C file from the
            //         // input
            //         fuzzer.handle_crash(&input, &mut fuzzvm, &crash_file)?;
            //     }
            // });
        }

        // Check if the input hit any kasan_report blocks
        if let Some(path) = fuzzvm.get_kasan_crash_path() {
            core_stats.lock().unwrap().crashes += 1;
            let mut input_bytes = Vec::new();
            input.to_bytes(&mut input_bytes)?;

            // Found a valid KASAN output, write out the crashing input
            kcov = kcov_addrs.iter().map(|&x| x as u64).collect();
            kcov.extend(sanitizer_bitmap_for_input.iter().map(|&x| x as u64));
            let mut hash_vec:Vec<u64> = kcov.iter().map(|&x| x as u64).collect();
            hash_vec.sort();
            let mut hasher = DefaultHasher::new();
            hash_vec.hash(&mut hasher);
            let kcov_hash = hasher.finish();
            let cov_report = get_kcov_string(&kcov, symbols);
            log::debug!("Got kcov hash: {kcov_hash}");
            if let Some(crash_file) =
            write_crash_input_cov(&crash_dir, Path::new(&crash_coverage_dir), &path, &input_bytes, &kcov_hash,&cov_report)?
            {
                // Inc the number of crashes found
                core_stats.lock().unwrap().crashes += 1;

                // Allow the fuzzer to handle the crashing state
                // Useful for things like syscall fuzzer to write a C file from the input
                fuzzer.handle_crash(&input, &mut fuzzvm, &crash_file)?;
            }
        } else if let Execution::CrashReset { path } = execution {
            // Inc the number of crashes found
            core_stats.lock().unwrap().crashes += 1;

            if !fuzzvm.console_output.is_empty() {
                if let Ok(_out) = std::str::from_utf8(&fuzzvm.console_output) {
                    // println!("{}", _out);
                }
            }

            let new_coverage: Vec<u64> = new_coverage_for_input.iter().map(|x| x.0).collect();

            let mut input_bytes = Vec::new();
            input.to_bytes(&mut input_bytes)?;

            // Attempt to write the crashing input and pass to fuzzer if it is a new input
            kcov = kcov_addrs.iter().map(|&x| x as u64).collect();
            kcov.extend(sanitizer_bitmap_for_input.iter().map(|&x| x as u64));
            let mut hash_vec:Vec<u64> = kcov.iter().map(|&x| x as u64).collect();
            hash_vec.sort();
            let mut hasher = DefaultHasher::new();
            hash_vec.hash(&mut hasher);
            let kcov_hash = hasher.finish();
            let cov_report = get_kcov_string(&kcov, symbols);
            log::debug!("Got kcov hash: {kcov_hash}");
            if let Some(crash_file) =
            write_crash_input_cov(&crash_dir, Path::new(&crash_coverage_dir), &path, &input_bytes, &kcov_hash,&cov_report)?
            {
                if SINGLE_STEP && SINGLE_STEP_DEBUG.load(Ordering::SeqCst) {
                    std::fs::write(crash_file.with_extension("single_step"), instrs.join("\n"))?;
                }

                // If this was a newly written crash file, allow the fuzzer to handle the
                // crashing state. Useful for things like syscall fuzzer to write a C
                // file from the input
                fuzzer.handle_crash(&input, &mut fuzzvm, &crash_file)?;

                let mutation_metadata = InputMetadata {
                    original_file,
                    mutation: mutation.clone(),
                    new_coverage,
                };

                // Write the metadata for this new input
                let metadata_path = project_dir.join("metadata");
                if !metadata_path.exists() {
                    let _ = std::fs::create_dir_all(&metadata_path);
                }

                // Get the fuzz hash for this input
                let hash = input.fuzz_hash();
                let filepath = metadata_path.join(format!("crash_{hash:016x}"));
                std::fs::write(filepath, serde_json::to_string(&mutation_metadata)?)?;
            }
        }

        let mut has_new_bits: bool = false;
        if sanitizer_bitmap.len() == 0 {
            has_new_bits = true;
            sanitizer_bitmap = sanitizer_bitmap_for_input.clone();
        } else {
            for idx in 0..sanitizer_bitmap_for_input.len() {
                let num1: u8 = sanitizer_bitmap[idx];
                let num2 = sanitizer_bitmap_for_input[idx];
                if num2 > num1{
                    has_new_bits = true;
                    sanitizer_bitmap[idx] = num2;
                }
            }
        }


        if interesting_kern_input || has_new_bits {
            // If we have a syscall sequence, that means we have a crash from syzkaller
            // And in that case, if we don't have a new syscall_sequence_score, we don't want to save the input
            if syscall_addr_sequence.len() == 0 || interesting_syscall_input == true {
                // TODO: Check if the argument values for syscalls is closer to the crashing syzprog
                // TODO: Check if the input trace is closer to the crashing input trace

                // Gather the mutation metadata for this iteration
                let new_coverage: Vec<u64> = new_coverage_for_input.iter().map(|x| x.0).collect();

                let mutation_metadata = InputMetadata {
                    original_file,
                    mutation,
                    new_coverage,
                };

                // Write the metadata for this new input
                let metadata_path = project_dir.join("metadata");
                if !metadata_path.exists() {
                    std::fs::create_dir_all(&metadata_path)?;
                }

                // Get the fuzz hash for this input
                let hash = input.fuzz_hash();
                let filepath = metadata_path.join(format!("{hash:016x}"));
                std::fs::write(filepath, serde_json::to_string(&mutation_metadata)?)?;

                // Save this input in the corpus dir
                //save_input_in_dir(&input, &corpus_dir)?;
                // Create a u64 array from the sanitizer_bitmap_for_input
                // Assuming sanitizer_bitmap_for_input is a Vec<u8> or &[u8]
                kcov = kcov_addrs.iter().map(|&x| x as u64).collect();
                kcov.extend(sanitizer_bitmap_for_input.iter().map(|&x| x as u64));
                let mut hash_vec:Vec<u64> = kcov.iter().map(|&x| x as u64).collect();
                hash_vec.sort();
                let mut hasher = DefaultHasher::new();
                hash_vec.hash(&mut hasher);
                let kcov_hash = hasher.finish();
                log::debug!("Got kcov hash: {kcov_hash}");
                let cov_report = get_kcov_string(&kcov, symbols);
                core_sync_corpus_set.push((input.clone(),kcov_hash,cov_report));
                corpus.push(input);
            }
        }

        if !fuzzvm.console_output.is_empty() {
            log::debug!("Console output!");
            unsafe {
                log::debug!(
                    "{:?}",
                    std::str::from_utf8_unchecked(&fuzzvm.console_output)
                );
            }
        }

        // Reset the guest state
        let guest_reset_perf = fuzzvm.reset_guest_state(&mut fuzzer)?;

        /// Small macro to add the various guest reset performance stats
        macro_rules! log_fuzzvm_perf_stats {
            ($mark:ident, $time:ident) => {
                core_stats
                    .lock()
                    .unwrap()
                    .perf_stats
                    .add(PerfMark::$mark, guest_reset_perf.$time);
            };
            ($mark:ident, init_guest.$time:ident) => {
                core_stats
                    .lock()
                    .unwrap()
                    .perf_stats
                    .add(PerfMark::$mark, guest_reset_perf.init_guest.$time);
            };
        }

        // Add the guest reset stats
        log_fuzzvm_perf_stats!(ResetGuestMemory, reset_guest_memory_restore);
        log_fuzzvm_perf_stats!(ResetCustomGuestMemory, reset_guest_memory_custom);
        log_fuzzvm_perf_stats!(ClearGuestMemory, reset_guest_memory_clear);
        log_fuzzvm_perf_stats!(GetDirtyLogs, get_dirty_logs);
        log_fuzzvm_perf_stats!(InitGuestRegs, init_guest.regs);
        log_fuzzvm_perf_stats!(InitGuestSregs, init_guest.sregs);
        log_fuzzvm_perf_stats!(InitGuestFpu, init_guest.fpu);
        log_fuzzvm_perf_stats!(InitGuestMsrs, init_guest.msrs);
        log_fuzzvm_perf_stats!(InitGuestDebugRegs, init_guest.msrs);
        log_fuzzvm_perf_stats!(ApplyFuzzerBreakpoint, apply_fuzzer_breakpoints);
        log_fuzzvm_perf_stats!(ApplyResetBreakpoint, apply_reset_breakpoints);
        log_fuzzvm_perf_stats!(ApplyCoverageBreakpoint, apply_coverage_breakpoints);
        log_fuzzvm_perf_stats!(InitVm, init_vm);
        core_stats.lock().unwrap().dirty_pages += try_u64!(guest_reset_perf.restored_pages);

        /*
        if guest_reset_perf.restored_pages > 60000 {
            let path = format!("dirty_pages_{}", guest_reset_perf.restored_pages);

            // Attempt to write the crashing input and pass to fuzzer if it is a new input
            if let Some(crash_file) = write_crash_input(crash_dir, &path, &input,
                &fuzzvm.console_output)? {

                if SINGLE_STEP_DEBUG.load(Ordering::SeqCst) {
                    std::fs::write(crash_file.with_extension("single_step"),
                        instrs.join("\n"))?;
                }
            }
        }
        */
    }

    // Append the current coverage
    core_stats.lock().unwrap().coverage.append(&mut coverage);
    // core_stats.lock().unwrap().redqueen_coverage.append(&mut redqueen_coverage);

    //// Write this current corpus to disk
    //for input in &corpus {
    //    save_input_in_dir(input, &corpus_dir)?;
    //}

    // Save the corpus in old_corpus for stats to sync with
    core_stats.lock().unwrap().old_corpus = Some(corpus);

    // Signal this thread is dead
    core_stats.lock().unwrap().alive = false;

    Ok(())
}
