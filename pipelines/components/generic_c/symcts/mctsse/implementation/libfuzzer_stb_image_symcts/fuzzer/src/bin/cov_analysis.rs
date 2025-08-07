//! A libfuzzer-like fuzzer with llmp-multithreading support and restarts
//! The example harness is built for `stb_image`.

#![feature(option_get_or_insert_default)]
#![feature(split_array)]

use libafl::{Error, prelude::ExitKind};
use libafl_bolts::format_duration_hms;
use mimalloc::MiMalloc;
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

use itertools::Itertools;
use std::{
    collections::HashMap,
    io::Write,
    os::linux::fs::MetadataExt,
    path::{PathBuf, Path},
    time::{SystemTime, UNIX_EPOCH}, str::FromStr, ops::{Not, BitAnd},
};
use symcts::standalone_cov_tracer::{TraceResult, TracedInput, Tracer};
use clap::{self, Parser};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
enum ExperimentLayoutMode {
    LocalExperiment,
    Magma,
    Fuzzbench,
    SingleRun,
}
impl FromStr for ExperimentLayoutMode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "local_experiment" => Ok(ExperimentLayoutMode::LocalExperiment),
            "magma" => Ok(ExperimentLayoutMode::Magma),
            "single" => Ok(ExperimentLayoutMode::SingleRun),
            "fuzzbench" => Ok(ExperimentLayoutMode::Fuzzbench),
            _ => Err(format!("Unknown experiment layout mode: {}", s)),
        }
    }
}

impl ToString for ExperimentLayoutMode {
    fn to_string(&self) -> String {
        match self {
            ExperimentLayoutMode::LocalExperiment => "local_experiment".to_string(),
            ExperimentLayoutMode::Magma => "magma".to_string(),
            ExperimentLayoutMode::Fuzzbench => "fuzzbench".to_string(),
            ExperimentLayoutMode::SingleRun => "single".to_string(),
        }
    }
}
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    // string instance prefix to strip off, optional, default="local_experiment_sync_"
    #[clap(long, default_value = "local_experiment_sync_")]
    instance_prefix: String,

    /// experiment layout mode
    #[clap(long, short, default_value = "local_experiment")]
    experiment_layout_mode: ExperimentLayoutMode,

    /// directory containing testcases
    #[clap()]
    directory: String,

    /// path to the cov binary
    #[clap()]
    cov_binary: PathBuf,

    #[clap(num_args = ..)]
    pub target_commandline: Vec<String>,
}

pub fn main() {
    env_logger::init();

    let mut args = Args::parse();
    args.directory = if args.directory.starts_with('/') {
        args.directory
    } else {
        format!("{}/{}", std::env::current_dir().unwrap().display(), args.directory)
    };
    args.cov_binary = args.cov_binary.canonicalize().unwrap();

    // create a temp dir
    let temp_dir = tempfile::tempdir().expect("Could not create temp dir");
    let temp_dir = temp_dir.path().to_path_buf();
    //cd to temp dir in case it tries to download any files
    std::env::set_current_dir(&temp_dir).expect("Could not cd to temp dir");
    println!("cd'ed to temp dir: {:?}", temp_dir);
    println!("Running cov analysis on {:?}, fuzz={:?}", args, &fuzz as *const _);

    fuzz(&args).expect("An error occurred while fuzzing");
}

pub type Target = Option<String>;
pub type TargetHarness = Option<String>;
pub type TargetTuple = (Target, TargetHarness);

pub type TrialNumber = usize;
pub type InstanceType = String;
pub type InstanceRunTuple = (InstanceType, TrialNumber);


#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct Classification {
    pub instance_type: String,
    pub instance_num: usize,
    pub constituent_fuzzer: String,
    pub target: Option<String>,
    pub target_harness: Option<String>,
    pub queue: String,
    pub file: String,
}
impl Classification {
    fn get_target_tuple(&self) -> TargetTuple {
        (self.target.clone(), self.target_harness.clone())
    }
}
trait ExperimentTracedInput {
    fn get_classification(&self, args: &Args) -> Classification;
    fn get_classification_local_experiment(&self, args: &Args) -> Classification;
    fn get_classification_magma(&self, args: &Args) -> Classification;
    fn get_classification_fuzzbench(&self, args: &Args) -> Classification;
    fn get_classification_single_run(&self, args: &Args) -> Classification;
}
impl ExperimentTracedInput for TracedInput {
    fn get_classification(&self, args: &Args) -> Classification {
        match args.experiment_layout_mode {
            ExperimentLayoutMode::LocalExperiment => self.get_classification_local_experiment(args),
            ExperimentLayoutMode::Magma => self.get_classification_magma(args),
            ExperimentLayoutMode::Fuzzbench => self.get_classification_fuzzbench(args),
            ExperimentLayoutMode::SingleRun => self.get_classification_single_run(args),
        }
    }
    fn get_classification_single_run(&self, args: &Args) -> Classification {
        let path = self
            .path
            .components()
            .map(|x| x.as_os_str().to_str().expect("not valid path component?"))
            .collect::<Vec<_>>();

        let (_prefix, [instance, _fuzzer, _queue, _file]) = path.rsplit_array_ref();
        let instance = instance.strip_prefix(&args.instance_prefix).unwrap_or(instance);

        Classification {
            instance_type: instance.to_string(),
            instance_num: 0,
            constituent_fuzzer: _fuzzer.to_string(),
            target: None,
            target_harness: None,
            queue: _queue.to_string(),
            file: _file.to_string(),
        }
    }
    fn get_classification_local_experiment(&self, args: &Args) -> Classification {
        // first, split off anything before the local_experiment_sync* directory
        let path = self
            .path
            .components()
            .map(|x| x.as_os_str().to_str().expect("not valid path component?"))
            .collect::<Vec<_>>();

        let (_prefix, [instance, _fuzzer, _queue, _file]) = path.rsplit_array_ref();
        let instance = instance.strip_prefix(&args.instance_prefix).unwrap();
        let (instance_type, _run) = instance
            .rsplit_once("_")
            .expect("Format is <instance>_<run>");

        Classification {
            instance_type: instance_type.to_string(),
            instance_num: usize::from_str(_run).expect("could not parse run number"),
            constituent_fuzzer: _fuzzer.to_string(),
            target: None,
            target_harness: None,
            queue: _queue.to_string(),
            file: _file.to_string(),
        }
    }
    fn get_classification_magma(&self, _args: &Args) -> Classification {
        // first, split off anything before the local_experiment_sync* directory
        let path = self
            .path
            .components()
            .map(|x| x.as_os_str().to_str().expect("not valid path component?"))
            .collect::<Vec<_>>();

        log::debug!("path: {:?}", path);

        let path_components = path.iter().filter(|x| x != &&"ball").collect::<Vec<_>>(); // if the unpacked ball directory is contained, skip it for parsing

        let (_prefix, [
                instance_type,
                target_dir,
                harness_dir,
                instance_num_dir,
                findings_dir,
                _fuzzer_dir,
                _queue,
                _file
            ]) = path_components.rsplit_array_ref();

        assert!(findings_dir == &&"findings");

        // let _full_instance = format!("{}_{}", instance_type, instance_num_dir);

        Classification {
            instance_type: instance_type.to_string(),
            instance_num: usize::from_str(instance_num_dir).expect("could not parse run number"),
            constituent_fuzzer: _fuzzer_dir.to_string(),
            target: Some(target_dir.to_string()),
            target_harness: Some(harness_dir.to_string()),
            queue: _queue.to_string(),
            file: _file.to_string(),
        }
    }

    fn get_classification_fuzzbench(&self, _args: &Args) -> Classification {
        // first, split off anything before the local_experiment_sync* directory
        let path = self
            .path
            .components()
            .map(|x| x.as_os_str().to_str().expect("not valid path component?"))
            .collect::<Vec<_>>();

        log::debug!("path: {:?}", path);

        let path_components = path.iter().filter(|x| x != &&"ball").collect::<Vec<_>>(); // if the unpacked ball directory is contained, skip it for parsing

        let (_prefix, [
                experiment_folders_dir,
                target_fuzzer_dir,
                trial_dir,
                corpus_dir,
                corpus_dir_cur,
                _fuzzer_dir,
                _queue,
                _file
            ]) = path_components.rsplit_array_ref();

        assert!(experiment_folders_dir == &&"experiment-folders", "expected experiment-folders, got {:?} in {:?}", experiment_folders_dir, path_components);
        assert!(corpus_dir == &&"corpus");
        assert!(corpus_dir_cur == &&"corpus");

        assert!(trial_dir.starts_with("trial-"));
        let trial_num = usize::from_str(trial_dir.strip_prefix("trial-").unwrap()).expect("could not parse trial num");
        let (target, instance_type) = target_fuzzer_dir.rsplit_once("-").unwrap();

        Classification {
            instance_type: instance_type.to_string(),
            instance_num: trial_num,
            constituent_fuzzer: _fuzzer_dir.to_string(),
            target: Some(target.to_string()),
            target_harness: None,
            queue: _queue.to_string(),
            file: _file.to_string(),
        }
    }
}

fn contains_symlink(path: &Path) -> bool {
    if path.is_symlink() {
        return true;
    }
    // check if any of the parent directories are symlinks
    let mut parent = path.parent();
    while let Some(p) = parent {
        if p.is_symlink() {
            return true;
        }
        parent = p.parent();
    }
    false
}

fn contains_hidden(path: &Path) -> bool {
    path.components().any(|x| {
        let s = x.as_os_str().to_str().unwrap();
        s.starts_with(".")
    })
}

pub fn get_experiment_inputs(dir: &str) -> Vec<(PathBuf, SystemTime)> {
    let glob_expr_afl_variants = format!("{}/**/id*", dir);
    // let glob_expr_centipede_libfuzzer = format!("{}/**/corpus/????????????????????????????????????????", dir);
    // let glob_expr_honggfuzz = format!("{}/**/corpus/*.honggfuzz.cov", dir);
    log::info!("Globbing for inputs: {}", glob_expr_afl_variants);
    let all_paths = glob::glob(&glob_expr_afl_variants)
        .unwrap()
        .into_iter()
        .filter_map(|x| x.ok())
        .filter(|path| path.metadata().is_ok())
        .filter(|path| !contains_symlink(path))
        .filter(|path| !contains_hidden(path))
        .filter(|path| !path.components().any(|c| c.as_os_str().to_str().unwrap().contains("symcc"))) // symcc cannot run alone, just rely on the fuzzers because it produces soooo many inputs
        .filter_map(|path| {
            // log::debug!("Found path: {:?}", path);
            let meta = path.metadata().expect("Could not get path metadata??");
            if meta.is_symlink() || !meta.is_file() {
                log::debug!("Skipping {:?} because it's not a file", path);
                return None;
            }
            if meta.st_size() > 0x10000 {
                log::warn!(
                    "File {:?} is too large at 0x{:x} bytes.",
                    path,
                    meta.st_size()
                );
                return None;
            }
            let timestamp = path.metadata().unwrap().modified().unwrap();
            Some((path, timestamp))
        })
        .sorted_by_key(|x| x.1)
        .collect::<Vec<_>>();

    all_paths
}

// pub fn trace_paths(paths: Vec<(PathBuf, SystemTime, Vec<u8>)>, forkserver_commandline: Vec<String>) ->

#[derive(Debug, Default)]
pub struct CumulativeResult {
    pub accumulated_by_label: HashMap<String, TraceResult>,
    pub first_seen_for_label: HashMap<String, SystemTime>,
    pub edge_first_seen_at_hit: HashMap<String, HashMap<usize, SystemTime>>,
    pub edge_first_seen_at_adj: HashMap<String, HashMap<usize, SystemTime>>,
    pub edge_first_seen_at_func: HashMap<String, HashMap<usize, SystemTime>>,
}
impl CumulativeResult {
    pub fn update(&mut self, label: &str, timestamp: SystemTime, result: &TraceResult) {
        self.first_seen_for_label.entry(label.to_string()).or_insert(timestamp);
        if !self.accumulated_by_label.contains_key(label) {
            self.accumulated_by_label.insert(label.to_string(), result.clone());
            assert!(
                self.edge_first_seen_at_hit.entry(label.to_owned()).or_default().is_empty() &&
                self.edge_first_seen_at_adj.entry(label.to_owned()).or_default().is_empty() &&
                self.edge_first_seen_at_func.entry(label.to_owned()).or_default().is_empty()
            );
            for hit_idx in result.hit_vec().iter_ones() {
                self.edge_first_seen_at_hit.entry(label.to_owned()).or_default().entry(hit_idx).or_insert(timestamp);
            }
            for adj_idx in result.adjacent_vec().iter_ones() {
                self.edge_first_seen_at_adj.entry(label.to_owned()).or_default().entry(adj_idx).or_insert(timestamp);
            }
            for func_idx in result.func_adjacent_vec().iter_ones() {
                self.edge_first_seen_at_func.entry(label.to_owned()).or_default().entry(func_idx).or_insert(timestamp);
            }
        } else {
            let existing = self.accumulated_by_label.get_mut(label).unwrap();
            let (novel_hit, novel_adj, novel_func) = existing.merge(result);
            for hit_idx in novel_hit.iter_ones() {
                self.edge_first_seen_at_hit.entry(label.to_owned()).or_default().entry(hit_idx).or_insert(timestamp);
            }
            for adj_idx in novel_adj.iter_ones() {
                self.edge_first_seen_at_adj.entry(label.to_owned()).or_default().entry(adj_idx).or_insert(timestamp);
            }
            for func_idx in novel_func.iter_ones() {
                self.edge_first_seen_at_func.entry(label.to_owned()).or_default().entry(func_idx).or_insert(timestamp);
            }
        }
    }
    pub fn update_for_classification(&mut self, classification: &Classification, timestamp: SystemTime, result: &TraceResult) {
        self.update(&classification.instance_type, timestamp, result);
        self.update(&format!("{}-{}", classification.instance_type, classification.instance_num), timestamp, result);
        self.update("all", timestamp, result);
    }
}

fn fuzz(args: &Args) -> Result<(), Error> {
    log::info!("Starting fuzz stuff: Running cov analysis on {:?}", args);
    let inputs = get_experiment_inputs(&args.directory);
    log::info!("Found {} inputs", inputs.len());
    let mut cmdline = vec![args.cov_binary.to_str().unwrap().to_owned()];
    cmdline.extend(args.target_commandline.clone());
    let mut tracer = Tracer::create(cmdline)?;
    let traced_inputs = inputs.iter().map(|x| tracer.trace_input(&x.0, x.1, true));

    let mut accumulated_bitmaps_by_classification = HashMap::<TargetTuple, CumulativeResult>::new();
    let mut result = HashMap::<TargetTuple, Vec::<(SystemTime, HashMap<InstanceType, (usize, usize, usize)>)>>::new();
    let start_time_tracing = SystemTime::now();
    for (i, input) in traced_inputs.into_iter().enumerate() {
        let input = input?;
        if input.exit_kind != ExitKind::Ok {
            log::warn!("Input {:?} exited with {:?}", input.path, input.exit_kind);
        }
        let classification = input.get_classification(&args);
        let time_traced_so_far = start_time_tracing
            .elapsed()
            .expect("Time went backwards?");
        let expected_time_total = time_traced_so_far
            * (inputs.len() as u32)
            / (i as u32 + 1);
        // let expected_time_left = expected_time_total - time_traced_so_far;
        log::info!(
            "{} / {} [{:?} so far, {:?} expected total, {:.2} exec/sec]: {} => {:?}",
            i,
            inputs.len(),
            format_duration_hms(&time_traced_so_far),
            format_duration_hms(&expected_time_total),
            i as f64 / time_traced_so_far.as_secs_f64(),
            input.path.display(),
            classification,
        );
        let target_ent = accumulated_bitmaps_by_classification
            .entry(classification.get_target_tuple())
            .or_default();

        target_ent.update_for_classification(&classification, input.timestamp, &input.result);

        for (_, target_data) in &accumulated_bitmaps_by_classification {
            let cur_state = target_data
            .accumulated_by_label
            .iter()
            .map(|(classification, trace_result)| {
                (
                    classification.clone(),
                    (
                        trace_result.num_hit(),
                        trace_result.num_adjacent(),
                        trace_result.num_func_adjacent(),
                    ),
                )
            })
            .collect::<HashMap<_, _>>();
            result.entry(classification.get_target_tuple()).or_insert_with(Vec::new).push((input.timestamp, cur_state));
        }
    }

    for (target, result) in result {
        let all_classifications = result
            .last()
            .unwrap()
            .1
            .keys()
            .cloned()
            .sorted_by_cached_key(|s| {
                let prekey = if s == "all" {
                    0
                } else if s.starts_with("afl") {
                    1
                } else if s.starts_with("symcc") {
                    2
                } else {
                    3
                };
                (prekey, s.clone())
            })
            .collect::<Vec<_>>();

        let path_prefix = format!("cov_analysis_{}{}", args.experiment_layout_mode.to_string(), match &target {
            (Some(target), Some(harness)) => format!("_target:{}_harness:{}", target, harness),
            (Some(target), None) => format!("_target:{}", target),
            (None, Some(harness)) => format!("_harness:{}", harness),
            (None, None) => format!(""),
        });

        let mut file_hit = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(format!("/tmp/{}_hit.csv", path_prefix))?;
        let mut file_adj = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(format!("/tmp/{}_adj.csv", path_prefix))?;
        let mut file_func = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(format!("/tmp/{}_func.csv", path_prefix))?;

        file_hit
            .write_all(format!("timestamp, {}\n", all_classifications.iter().join(", ")).as_bytes())?;
        file_adj
            .write_all(format!("timestamp, {}\n", all_classifications.iter().join(", ")).as_bytes())?;
        file_func
            .write_all(format!("timestamp, {}\n", all_classifications.iter().join(", ")).as_bytes())?;

        for (time_modified, cur_state) in result {
            let timestamp = time_modified
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let mut line_hit = format!("{:?}", timestamp);
            let mut line_adj = line_hit.clone();
            let mut line_func = line_hit.clone();
            for classification in &all_classifications {
                let (hit, adjacent, func_adjacent) =
                    cur_state.get(classification).unwrap_or(&(0, 0, 0));
                line_hit.push_str(&format!(", {}", hit));
                line_adj.push_str(&format!(", {}", adjacent));
                line_func.push_str(&format!(", {}", func_adjacent));
            }
            file_hit.write_all(format!("{}\n", line_hit).as_bytes())?;
            file_adj.write_all(format!("{}\n", line_adj).as_bytes())?;
            file_func.write_all(format!("{}\n", line_func).as_bytes())?;
        }

        // compute NxN overlap matrix
        let mut overlap_matrix_hit =
            vec![vec![0; all_classifications.len()]; all_classifications.len()];
        let mut overlap_matrix_adjacent =
            vec![vec![0; all_classifications.len()]; all_classifications.len()];
        let mut overlap_matrix_func =
            vec![vec![0; all_classifications.len()]; all_classifications.len()];
        for (i, classification_i) in all_classifications.iter().enumerate() {
            for (j, classification_j) in all_classifications.iter().enumerate() {
                let bitmap_triple_i = accumulated_bitmaps_by_classification[&target].accumulated_by_label.get(classification_i);
                let bitmap_triple_j = accumulated_bitmaps_by_classification[&target].accumulated_by_label.get(classification_j);

                let (hit_vec_i, adj_vec_i, func_adj_vec_i) = match bitmap_triple_i {
                    Some(TraceResult::Compressed {
                        hit_vec,
                        adjacent_vec,
                        func_adjacent_vec,
                    }) => (hit_vec, adjacent_vec, func_adjacent_vec),
                    _ => panic!("Expected compressed trace result"),
                };
                let (hit_vec_j, adj_vec_j, func_adj_vec_j) = match bitmap_triple_j {
                    Some(TraceResult::Compressed {
                        hit_vec,
                        adjacent_vec,
                        func_adjacent_vec,
                    }) => (hit_vec, adjacent_vec, func_adjacent_vec),
                    _ => panic!("Expected compressed trace result"),
                };
                let hit_overlap = hit_vec_j.clone().not().bitand(hit_vec_i);
                let adjacent_overlap = adj_vec_j.clone().not().bitand(adj_vec_i);
                let func_adjacent_overlap = func_adj_vec_j.clone().not().bitand(func_adj_vec_i);
                overlap_matrix_hit[i][j] = hit_overlap.count_ones();
                overlap_matrix_adjacent[i][j] = adjacent_overlap.count_ones();
                overlap_matrix_func[i][j] = func_adjacent_overlap.count_ones();
            }
        }

        //output it to csvs
        let mut file_hit = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(format!("/tmp/{}_overlap_hit.csv", path_prefix))?;
        let mut file_adjacent = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(format!("/tmp/{}_overlap_adj.csv", path_prefix))?;
        let mut file_func_adjacent = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(format!("/tmp/{}_overlap_func.csv", path_prefix))?;
        file_hit.write_all(format!("%, {}\n", all_classifications.iter().join(", ")).as_bytes())?;
        file_adjacent
            .write_all(format!("%, {}\n", all_classifications.iter().join(", ")).as_bytes())?;
        file_func_adjacent
            .write_all(format!("%, {}\n", all_classifications.iter().join(", ")).as_bytes())?;

        for (i, classification_i) in all_classifications.iter().enumerate() {
            let mut line_hit = classification_i.clone();
            let mut line_adjacent = classification_i.clone();
            let mut line_func_adjacent = classification_i.clone();
            for (j, _classification_j) in all_classifications.iter().enumerate() {
                line_hit.push_str(&format!(", {}", overlap_matrix_hit[i][j]));
                line_adjacent.push_str(&format!(", {}", overlap_matrix_adjacent[i][j]));
                line_func_adjacent.push_str(&format!(", {}", overlap_matrix_func[i][j]));
            }
            file_hit.write_all(format!("{}\n", line_hit).as_bytes())?;
            file_adjacent.write_all(format!("{}\n", line_adjacent).as_bytes())?;
            file_func_adjacent.write_all(format!("{}\n", line_func_adjacent).as_bytes())?;
        }
        //output it to csvs
        let mut file_hit = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(format!("/tmp/{}_by_edge_hit.csv", path_prefix))?;
        let mut file_adjacent = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(format!("/tmp/{}_by_edge_adj.csv", path_prefix))?;
        let mut file_func_adjacent = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(format!("/tmp/{}_by_edge_func.csv", path_prefix))?;
        file_hit.write_all(format!("%, {}\n", all_classifications.iter().join(", ")).as_bytes())?;
        file_adjacent
            .write_all(format!("%, {}\n", all_classifications.iter().join(", ")).as_bytes())?;
        file_func_adjacent
            .write_all(format!("%, {}\n", all_classifications.iter().join(", ")).as_bytes())?;

        for (i, classification_i) in all_classifications.iter().enumerate() {
            let mut line_hit = classification_i.clone();
            let mut line_adjacent = classification_i.clone();
            let mut line_func_adjacent = classification_i.clone();
            for (j, _classification_j) in all_classifications.iter().enumerate() {
                line_hit.push_str(&format!(", {}", overlap_matrix_hit[i][j]));
                line_adjacent.push_str(&format!(", {}", overlap_matrix_adjacent[i][j]));
                line_func_adjacent.push_str(&format!(", {}", overlap_matrix_func[i][j]));
            }
            file_hit.write_all(format!("{}\n", line_hit).as_bytes())?;
            file_adjacent.write_all(format!("{}\n", line_adjacent).as_bytes())?;
            file_func_adjacent.write_all(format!("{}\n", line_func_adjacent).as_bytes())?;
        }


        // dump the first-time-seen for each edge to CSVs
        for (_target, accumulated_bitmap) in accumulated_bitmaps_by_classification.iter() {
            let header = format!("edge_id, {}\n", all_classifications.iter().join(", "));
            let mut file_hit = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(format!("/tmp/{}_edge_first_seen_hit.csv", path_prefix))?;
            let mut file_adjacent = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(format!("/tmp/{}_edge_first_seen_adj.csv", path_prefix))?;
            let mut file_func_adjacent = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(format!("/tmp/{}_edge_first_seen_func.csv", path_prefix))?;

            file_hit.write_all(header.as_bytes())?;
            file_adjacent.write_all(header.as_bytes())?;
            file_func_adjacent.write_all(header.as_bytes())?;

            let all_edges = accumulated_bitmap.edge_first_seen_at_hit.iter()
                                .map(|(_label, by_edge)| by_edge.keys())
                                .flatten()
                                .unique()
                                .sorted()
                                .collect::<Vec<_>>();

            for edge in all_edges {
                let mut line_hit = format!("0x{:x}", edge);
                let mut line_adj = line_hit.to_owned();
                let mut line_func = line_hit.to_owned();
                for (_i, classification_i) in all_classifications.iter().enumerate() {
                    let first_hit = accumulated_bitmap
                                        .edge_first_seen_at_hit
                                        .get(classification_i)
                                        .map(|x| x.get(edge))
                                        .flatten()
                                        .map(|x| x.duration_since(UNIX_EPOCH).unwrap().as_secs().to_string());
                    let first_adj = accumulated_bitmap
                                        .edge_first_seen_at_adj
                                        .get(classification_i)
                                        .map(|x| x.get(edge))
                                        .flatten()
                                        .map(|x| x.duration_since(UNIX_EPOCH).unwrap().as_secs().to_string());
                    let first_func = accumulated_bitmap
                                        .edge_first_seen_at_func
                                        .get(classification_i)
                                        .map(|x| x.get(edge))
                                        .flatten()
                                        .map(|x| x.duration_since(UNIX_EPOCH).unwrap().as_secs().to_string());
                    line_hit.push_str(&format!(", {}", first_hit.unwrap_or("".to_owned())));
                    line_adj.push_str(&format!(", {}", first_adj.unwrap_or("".to_owned())));
                    line_func.push_str(&format!(", {}", first_func.unwrap_or("".to_owned())));
                }
                file_hit.write_all(format!("{}\n", line_hit).as_bytes())?;
                file_adjacent.write_all(format!("{}\n", line_adj).as_bytes())?;
                file_func_adjacent.write_all(format!("{}\n", line_func).as_bytes())?;
            }
        }
    }

    Ok(())
    // plot the results
}