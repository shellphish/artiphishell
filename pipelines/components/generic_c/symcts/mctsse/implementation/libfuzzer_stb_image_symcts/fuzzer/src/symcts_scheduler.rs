use std::cmp::min;
use std::io::Write;
use std::marker::PhantomData;
use std::time::{SystemTime, UNIX_EPOCH};

use itertools::{Itertools, MinMaxResult};
use libafl::corpus::{Corpus, CorpusId};
use libafl::prelude::{UsesInput, HasTestcase, HasTargetBytes, HasBytesVec};
use libafl::schedulers::Scheduler;
use libafl::state::{HasCorpus, HasMetadata, HasRand, UsesState, BetterStateTrait};
use libafl::{Error};
use libafl_bolts::HasLen;
use rand::prelude::SliceRandom;

use crate::coverage::{CoveragePoint, CoverageSummary};
use crate::metadata::global::{SyMCTSGlobalMetadata, CoverageLocationInfo, register_new_interesting_inputs, register_symbolic_mutation_scheduling_of_testcase};
use crate::symcts_mutations::MutationResultMetadata;
use crate::util::hash_target_bytes_input;


#[derive(Debug, Default, Clone, Copy)]
pub struct SyMCTSScheduler<S> {
    phantom: PhantomData<S>,
}

impl<S> SyMCTSScheduler<S> {
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

impl<S> UsesState for SyMCTSScheduler<S>
where
    S: UsesInput,
{
    type State = S;
}

fn num_times_scheduled_for_mutation<C: Corpus>(corpus: &C, id: CorpusId) -> usize {
    corpus
        .get(id)
        .unwrap()
        .borrow()
        .metadata::<MutationResultMetadata>()
        .unwrap()
        .num_times_scheduled_for_mutation
}
fn trace_len<C: Corpus>(corpus: &C, id: CorpusId) -> usize {
    corpus
        .get(id)
        .unwrap()
        .borrow()
        .metadata::<CoverageSummary>()
        .unwrap()
        .trace_length
}

fn input_len<C: Corpus>(corpus: &C, id: CorpusId) -> usize {
    corpus
        .get(id)
        .unwrap()
        .borrow()
        .metadata::<CoverageSummary>()
        .unwrap()
        .input_length
}

impl<S> Scheduler for SyMCTSScheduler<S>
where
    S: HasCorpus + HasRand + HasMetadata + HasTestcase + BetterStateTrait,
    S::Input: HasLen + HasBytesVec,
{
    fn next(&mut self, state: &mut Self::State) -> Result<CorpusId, Error> {
        assert!(!state.corpus().is_empty());
        let (_rand, corpus, state_metadata) = state.get_state_components_rand_corpus_metadata();
        let global_meta: &mut SyMCTSGlobalMetadata =
            state_metadata.get_mut::<SyMCTSGlobalMetadata>().unwrap();

        let queue_len = global_meta.synced_inputs_queue.len();
        global_meta.synced_inputs_queue.rotate_right(min(10, queue_len));
        global_meta.synced_inputs_queue.truncate(10);

        // let current_tick = global_meta.total_num_times_sampled;

        let covered_ids = global_meta
            .coverage_point_info
            .iter_mut()
            .filter(|(_, cov_info)| cov_info
                                        .filtered_covering_corpus_ids(|&id| num_times_scheduled_for_mutation(corpus, id) == 0)
                                        .len() > 0);

        #[cfg(feature="scheduling_weight_function_sampling_counts")]
        let weight_function = |(_cov_point, cov_info): &(&CoveragePoint, &mut CoverageLocationInfo)|  {
            let weight_sampled = (cov_info.num_times_symbolically_sampled * 100).pow(2);
            let weight_traced = cov_info.num_times_coverage_traced - cov_info.coverage_min_max_tracker.as_ref().unwrap().corpus().len();
            // let ticks_since_last_seen = (current_tick - cov_info.tick_last_seen_mutated);
            weight_sampled + weight_traced + (_cov_point.bucketed_count as usize)
        };
        // #[cfg(feature="scheduling_weight_function_percent_unmutated")]
        // let weight_function = |(_cov_point, cov_info): &(&CoveragePoint, &mut CoverageLocationInfo)| {
        //     let numerator = cov_info.filtered_covering_corpus_ids(|&id| num_times_scheduled_for_mutation(corpus, id) == 0).len();
        //     let denominator = cov_info.coverage_min_max_tracker.corpus().len();
        //     ((numerator as f64 / denominator as f64) * 10000.) as usize
        // };
        #[cfg(feature="scheduling_weight_function_least_unmutated")]
        let weight_function = |(_cov_point, cov_info): &(&CoveragePoint, &mut CoverageLocationInfo)| {
            let num_mutated = cov_info.filtered_covering_corpus_ids(|&id| num_times_scheduled_for_mutation(corpus, id) > 0).len();
            let num_not_mutated = cov_info.coverage_min_max_tracker.corpus().len() - num_mutated;
            num_not_mutated
        };

        let mut ids = covered_ids
            .collect::<Vec<_>>();
        #[cfg(feature="scheduling_weighted_random")]
        let max_weight = ids.iter().map(weight_function).max().unwrap() + 1;
        ids.shuffle(&mut rand::thread_rng());
        // println!("ids={:?}", ids);

        #[cfg(feature="scheduling_weighted_minimum")]
        let scheduled = ids
            .into_iter()
            .min_by_key(weight_function);

        #[cfg(feature="scheduling_weighted_random")]
        let scheduled = ids
            .choose_weighted_mut(&mut rand::thread_rng(), |x| max_weight - weight_function(x));

        #[cfg(feature="scheduling_uniform_random")]
        let scheduled = ids.into_iter().next();


        let sched_log_path = global_meta.sync_dir.join(".scheduler.log");
        let cur_time = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();

        if let Some((scheduled_coverage_point, scheduled_coverage_info)) = scheduled {

            //////////////////////////////////////////////
            // println!("scheduled_coverage_info={:?}", scheduled_coverage_info);
            // randomly pick a corpusid from scheduled_coverage_info.coverage_min_max_tracker.corpus()
            let untraced_corpus = scheduled_coverage_info
                .filtered_covering_corpus_ids(|&id| num_times_scheduled_for_mutation(corpus, id) == 0);

            log::debug!("avail_corpus={:?}", untraced_corpus
                .iter()
                .map(|&id| format!("{:?} => {:?}", id, corpus.get(id).unwrap().borrow().metadata::<MutationResultMetadata>()))
                .collect::<Vec<_>>()
            );

            let untraced_corpus = untraced_corpus
                .into_iter()
                .map(|id| (id, trace_len(corpus, id)))
                .collect::<Vec<_>>();
            let minmax_result = untraced_corpus.iter().map(|x| x.1).minmax();
            let least_covered_id = match minmax_result {
                MinMaxResult::NoElements => panic!("no elements in untraced corpus"),
                MinMaxResult::OneElement(_x) => {
                    let id = untraced_corpus.choose(&mut rand::thread_rng()).unwrap().0;
                    id
                },
                MinMaxResult::MinMax(min, max) => {
                    assert!(min <= max);
                    let id = untraced_corpus.choose_weighted(&mut rand::thread_rng(), |x| {
                        1 + max - x.1
                    }).unwrap().0;
                    id
                }
            };


            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(sched_log_path)
                .unwrap();
            file.write_all(format!("{}\t{}\t{}\t{:?}\t{:?}\t{:?}\n",
                cur_time,
                scheduled_coverage_info.num_times_symbolically_sampled,
                scheduled_coverage_info.num_times_coverage_traced,
                scheduled_coverage_point,
                least_covered_id,
                scheduled_coverage_info.coverage_min_max_tracker.as_ref().expect("should be set in on_add").corpus()).as_bytes()
            ).unwrap();
            log::info!(
                target: "symcts_scheduler",
                "Picked: {:#?}: {:#?} => {:#?} [#corpus: {:?}, #untraced: {:?}]",
                &scheduled_coverage_point,
                &scheduled_coverage_info,
                &least_covered_id,
                scheduled_coverage_info.coverage_min_max_tracker.as_ref().expect("should be set in on_add").corpus().len(),
                untraced_corpus.len(),
            );

            global_meta.last_scheduled = Some((scheduled_coverage_point.clone(), least_covered_id.clone()));

            register_symbolic_mutation_scheduling_of_testcase(
                state,
                least_covered_id,
                true, // scheduled to be mutated by THIS instance
            );

            return Ok(least_covered_id.clone());
        }
        else {
            // okay, so we completely ran out of things to solve. Let's just randomly pick inputs to solve for, while
            // we wait for a miracle input to be found, either by us or an external fuzzer.
            // we weight towards longer inputs because there's likely more possible mutations there.
            log::warn!(
                target: "symcts_scheduler",
                "No coverage points left to solve for. Picking random input to continue."
            );
            let corpus = state.corpus();
            let corpus_ids = corpus.ids().map(|id| (id, input_len(corpus, id))).collect::<Vec<_>>();

            let (corpus_id, _length) = corpus_ids
                .choose_weighted(&mut rand::thread_rng(), |x| x.1)
                .expect("How can there be no inputs at all in the corpus??");

            return Ok(*corpus_id)
        }
    }

    fn on_add(&mut self, state: &mut Self::State, inserted_idx: CorpusId) -> Result<(), libafl::Error> {
        let input_hash = {
            let mut testcase = state.corpus().get(inserted_idx).unwrap().borrow_mut();
            hash_target_bytes_input(testcase.load_input(state.corpus())?)
        };
        let global_meta = state
            .metadata_mut::<SyMCTSGlobalMetadata>()
            .expect("No global metadata set??");

        global_meta.hash_to_corpus_id.insert(input_hash, inserted_idx);

        let (cov_summary, single_cov) = global_meta
            .last_traced_cov
            .take()
            .expect("The scheduler on_add should only run after the feedback has populated its last_cov.");

        register_new_interesting_inputs(state, vec![(inserted_idx, cov_summary, single_cov)]);
        state
            .corpus_mut()
            .get(inserted_idx)
            .unwrap()
            .borrow_mut()
            .add_metadata(MutationResultMetadata::default());
        Ok(())
    }

    /// Set current fuzzed corpus id and `scheduled_count`
    fn set_current_scheduled(
        &mut self,
        state: &mut Self::State,
        next_idx: Option<CorpusId>,
    ) -> Result<(), Error> {
        let current_idx = *state.corpus().current();

        if let Some(idx) = current_idx {
            let mut testcase = state.testcase_mut(idx)?;
            let scheduled_count = testcase.scheduled_count();

            // increase scheduled count, this was fuzz_level in afl
            testcase.set_scheduled_count(scheduled_count + 1);
        }

        *state.corpus_mut().current_mut() = next_idx;
        Ok(())
    }
}
