//! Map feedback, maximizing or minimizing maps, for example the afl-style map observer.
use crate::coverage::CoverageMinMaxTracker;
use crate::coverage::{CoveragePoint, CoverageSummary, SingleCoverage};
use crate::symcts_mutations::MutationResultMetadata;
use core::fmt::Debug;
use std::path::PathBuf;
use libafl_bolts::HasLen;
use libafl::corpus::{Corpus, CorpusId};
use libafl::prelude::UsesInput;
use libafl::state::{HasCorpus, HasMetadata, HasRand, BetterStateTrait};
use libafl_bolts::impl_serdeany;
use serde::ser::SerializeMap;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Serialize, Deserialize, Clone)]
pub struct CoverageLocationInfo {
    pub num_times_symbolically_sampled: usize,
    pub num_times_coverage_traced: usize,
    pub tick_last_seen_mutated: usize,
    pub coverage_min_max_tracker: Option<CoverageMinMaxTracker>,
}
impl_serdeany!(CoverageLocationInfo);

impl core::fmt::Debug for CoverageLocationInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f
            .debug_struct("CoverageLocationInfo")
                .field("min_max_coverage", &self.coverage_min_max_tracker)
                .field("num_times_symbolically_sampled", &self.num_times_symbolically_sampled)
                .field("num_times_coverage_traced", &self.num_times_coverage_traced).finish()
    }
}

impl CoverageLocationInfo {
    pub fn filtered_covering_corpus_ids(&self, predicate: impl Fn(&CorpusId) -> bool) -> Vec<CorpusId> {
        self.coverage_min_max_tracker.as_ref().unwrap().filtered_covering_corpus_ids(predicate)
    }
    pub fn update_testcase_for_newly_triggered_coverage_points(
        &mut self,
        corpus_id: CorpusId,
        cov: &SingleCoverage,
        _input_size: usize,
    ) {
        match self.coverage_min_max_tracker {
            Some(ref mut tracker) => {
                tracker.add(&cov, corpus_id);
            }
            None => {
                self.coverage_min_max_tracker = Some(
                    CoverageMinMaxTracker::create(cov, corpus_id)
                );
            }
        }
    }
}

// TODO maybe use bignums instead of just usize, for now use `checked_add` to see if necessary
#[derive(Default, Debug, Deserialize, Clone)]
pub struct SyMCTSGlobalMetadata {
    pub sync_dir: PathBuf,
    pub coverage_point_info: HashMap<CoveragePoint, CoverageLocationInfo>,
    pub total_num_times_sampled: usize,
    pub total_num_times_traced: usize,
    pub total_num_times_crashed: usize,
    pub total_num_times_timed_out: usize,
    pub synced_inputs_queue: Vec<CorpusId>,
    pub last_tick_seen_new_branch: usize,
    pub last_scheduled: Option<(CoveragePoint, CorpusId)>,
    pub last_traced_cov: Option<(CoverageSummary, SingleCoverage)>,
    pub hash_to_corpus_id: HashMap<u64, CorpusId>,

    // how many times did we trace it, how many times did the other instances trace it
    pub traced_inputs: HashMap<u64, (usize, usize)>,
}
impl_serdeany!(SyMCTSGlobalMetadata);

impl SyMCTSGlobalMetadata {
    pub fn current_tick(&self) -> usize {
        self.total_num_times_sampled
    }
    pub fn increment_tick(&mut self) {
        self.total_num_times_sampled += 1;
    }
    pub fn seems_stuck(&self) -> bool {
        let seems_stuck = self.last_tick_seen_new_branch + 10 < self.current_tick();
        log::info!(
            "last_tick_seen_new_branch: {}, current_tick: {} => stuck: {}",
            self.last_tick_seen_new_branch,
            self.current_tick(),
            seems_stuck
        );
        seems_stuck
    }
    pub fn reset_stuck_counter(&mut self) {
        self.last_tick_seen_new_branch = self.current_tick();
    }
    pub fn register_traced_by_us(&mut self, hash: u64) {
        let (traced_by_us, traced_by_others) = self.traced_inputs
            .entry(hash)
            .or_default();
        *traced_by_us += 1;
    }
    pub fn get_traced_by_us(&self, hash: u64) -> usize {
        self.traced_inputs
            .get(&hash)
            .map(|(traced_by_us, _)| *traced_by_us)
            .unwrap_or(0)
    }
    pub fn register_traced_by_others(&mut self, hash: u64) {
        let (traced_by_us, traced_by_others) = self.traced_inputs
            .entry(hash)
            .or_default();
        *traced_by_others += 1;
    }
    pub fn get_traced_by_others(&self, hash: u64) -> usize {
        self.traced_inputs
            .get(&hash)
            .map(|(_, traced_by_others)| *traced_by_others)
            .unwrap_or(0)
    }
}

impl Serialize for SyMCTSGlobalMetadata {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer {
            let mut map = serializer.serialize_map(Some(self.coverage_point_info.len()))?;
            for (k, v) in &self.coverage_point_info {
                map.serialize_entry(&format!("{:?}", k), v)?;
            }
            map.end()
    }
}

pub fn register_symbolic_mutation_scheduling_of_testcase<S>(state: &mut S, sampled_id: CorpusId, from_this_instance: bool)
where
    S: HasCorpus + HasMetadata + BetterStateTrait,
{
    let (_rng, corpus, meta) = state.get_state_components_rand_corpus_metadata();

    corpus
        .get(sampled_id)
        .expect(format!("How did we sample a non-existing corpus id: {:?}??", sampled_id).as_str())
        .borrow_mut()
        .metadata_mut::<MutationResultMetadata>()
        .unwrap().num_times_scheduled_for_mutation += 1;

    if !from_this_instance {
        // if a different process is tracing this input, we want to track that this specific input was traced, but we want to keep our own input distribution separate. That way we still use our tracing opportunity for the target branch, but we do it with a different input instead.
        return;
    }

    // TODO: send custom event letting other instances now that this testcase has been scheduled for mutation already

    let testcase = corpus.get(sampled_id).unwrap().borrow();

    let cov_summary = testcase.metadata::<CoverageSummary>().unwrap().clone();

    let global_meta = meta
        .get_mut::<SyMCTSGlobalMetadata>()
        .unwrap();

    global_meta.increment_tick();
    for cov_point in cov_summary.points.iter() {
        let v = global_meta
            .coverage_point_info
            .get_mut(cov_point)
            .unwrap_or_else(|| {
                panic!(
                    "Coverage point {:?} from {:?} not found in global metadata when trying to register symbolic sampling, should always have been added when it was first traced instead!", cov_point, sampled_id);
            });
        v.num_times_symbolically_sampled += 1;
    }
}

pub fn register_new_interesting_inputs<S>(state: &mut S, traced_inputs: Vec<(CorpusId, CoverageSummary, SingleCoverage)>)
where
    S: UsesInput + HasCorpus + HasMetadata + HasRand + BetterStateTrait,
    S::Input: HasLen
{
    let (_, corpus_ref, state_metadata) = state.get_state_components_rand_corpus_metadata();

    let global_meta = state_metadata.get_mut::<SyMCTSGlobalMetadata>().unwrap();

    for (corpus_id, cov_summary, cov_map) in traced_inputs.into_iter() {
        let mut testcase = corpus_ref.get(corpus_id).unwrap().borrow_mut();
        let input_size = testcase.load_input(corpus_ref).expect("could not load testcase input").len();

        // println!("Traced input: {:?}, tc_meta: {:?}", testcase.input(), &tc_meta);
        for cov_point in cov_summary.points.iter() {
            let cov_info = global_meta
                .coverage_point_info
                .entry(cov_point.clone())
                .or_insert_with(|| CoverageLocationInfo {
                    num_times_symbolically_sampled: 0,
                    num_times_coverage_traced: 1,
                    tick_last_seen_mutated: 0,
                    coverage_min_max_tracker: Some(CoverageMinMaxTracker::create(
                        &cov_map,
                        corpus_id
                    )),
                });
            cov_info.update_testcase_for_newly_triggered_coverage_points(corpus_id, &cov_map, input_size);
        }
        testcase.add_metadata(cov_summary);
    }

}
