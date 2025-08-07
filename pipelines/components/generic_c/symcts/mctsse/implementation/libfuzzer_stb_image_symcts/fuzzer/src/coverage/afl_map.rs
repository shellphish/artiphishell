use std::{marker::PhantomData, collections::HashSet};

use libafl_bolts::{HasLen, rands::Rand, impl_serdeany, Named, AsIter, AsSlice};
use libafl::{observers::StdMapObserver, state::{HasClientPerfMonitor, HasMetadata, HasRand, BetterStateTrait}, feedbacks::Feedback, monitors::UserStats, events::Event, prelude::{UsesInput, ObserversTuple, EventFirer, HasTargetBytes}};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::metadata::global::SyMCTSGlobalMetadata;

use super::{SyMCTSTestCaseAnnotationFeedback, CoverageSummary, loop_bucketing::get_bucketed_hitcount_outer, SingleCoverage};

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub struct AFLBitmapCoveragePoint {
    pub branch_index: usize,
    pub bucketed_count: usize,
    // pub reached_adjacent_edge: bool,
    // pub reached_function: bool,
}

impl AFLBitmapCoveragePoint {
    pub fn new(branch_index: usize, bitmap_entry: u32) -> Option<Self> {
        if bitmap_entry == 0 {
            return None;
        }
        let reached_adjacent_edge: bool = (bitmap_entry & (1 << 31)) != 0;
        let count = (bitmap_entry & 0x3FFFFFFF) as usize;
        if count == 0 && !reached_adjacent_edge {
            return None;
        }

        let bucketed_count = get_bucketed_hitcount_outer(count);

        return Some(AFLBitmapCoveragePoint {
            branch_index,
            bucketed_count,
        });
    }
}

impl core::fmt::Debug for AFLBitmapCoveragePoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:x} * {}", self.branch_index, self.bucketed_count)
    }
}
impl core::fmt::Display for AFLBitmapCoveragePoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <Self as core::fmt::Debug>::fmt(&self, f)
    }
}


#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AFLBitmapCoverageMetadata {
    pub coverage_summary: CoverageSummary,
}
impl_serdeany!(AFLBitmapCoverageMetadata);

#[derive(Debug)]
pub struct SyMCTSAFLBitmapCoverageFeedback {
    name: String,
    map_observer_name: String,
    last_cov: Option<(CoverageSummary, SingleCoverage)>,
}

impl SyMCTSAFLBitmapCoverageFeedback {
    /// Creates a concolic feedback from an observer
    #[allow(unused)]
    #[must_use]
    pub fn for_afl_bitmap_observer<T>(observer: &StdMapObserver<T, false>) -> Self
    where
        T: Serialize + DeserializeOwned + Default + Copy,
    {
        Self {
            name: format!("SyMCTSFeedback_afl_{}", observer.name()),
            map_observer_name: observer.name().to_owned(),
            last_cov: None,
        }
    }

    pub fn take_last_cov(&mut self) -> Option<(CoverageSummary, SingleCoverage)>{
        self.last_cov.take()
    }
}

impl Named for SyMCTSAFLBitmapCoverageFeedback {
    fn name(&self) -> &str {
        &self.name
    }
}


impl SyMCTSTestCaseAnnotationFeedback for SyMCTSAFLBitmapCoverageFeedback {
    fn get_coverage_points<S, OT>(
        &self, input: &S::Input, observers: &OT
    ) -> Result<(CoverageSummary, SingleCoverage), libafl::Error>
    where
        S: UsesInput,
        <S as UsesInput>::Input: HasLen,
        OT: libafl::observers::ObserversTuple<S>,
    {
        let map_metadata = observers
            .match_name::<StdMapObserver<u32, false>>(&self.map_observer_name)
            .ok_or_else( || libafl::Error::illegal_state("Must have hitcounts map observer!"))?;

        // println!("Non-zero map entries: {:#?}", map_metadata.as_iter().enumerate().filter(|(idx, count)| **count != 0).map(|x| x.0).collect::<Vec<_>>());

        let coverage_points = map_metadata
            .as_iter()
            .enumerate()
            .filter_map(|(byte_idx, count)| AFLBitmapCoveragePoint::new(byte_idx, *count))
            .collect::<HashSet<AFLBitmapCoveragePoint>>();

        // log::debug!(target: "symcts_feedback", "Coverage points: {:?}", coverage_points.iter().sorted().collect::<Vec<_>>());

        let single_cov_map = SingleCoverage::from_shm_slice(input.len(), map_metadata.as_slice());
        Ok((CoverageSummary {
            points: coverage_points,
            trace_length: single_cov_map.non_zero_bitmap.count_ones(), // approximate trace length: the number of branches hit
            input_length: map_metadata.as_slice().len(),
        }, single_cov_map))
    }
}

impl<S> Feedback<S> for SyMCTSAFLBitmapCoverageFeedback
where
    S: UsesInput + HasClientPerfMonitor + HasMetadata + HasRand + BetterStateTrait,
    S::Input: HasLen + HasTargetBytes
{
    fn init_state(&mut self, _state: &mut S) -> Result<(), libafl::Error> {
        _state
            .add_metadata(SyMCTSGlobalMetadata::default());
        Ok(())
    }

    fn is_interesting<EM, OT>(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        input: &EM::Input,
        observers: &OT,
        exit_kind: &libafl::executors::ExitKind,
    ) -> Result<bool, libafl::Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
    {
        log::debug!(target: "symcts_feedback", "Target reported exit kind of {:?}", exit_kind);
        let (cov_summary, single_cov) = self.get_coverage_points(input, observers)?;
        let (modified_global, _testcase_len) = self.record_metadata(
            state, input, observers,
            &cov_summary, &single_cov,
            exit_kind
        )?;

        log::debug!(target: "symcts_feedback", "Coverage summary: {:?}", cov_summary);

        if modified_global || state.rand_mut().next() % 100 == 0 {
            manager.fire(
                state,
                Event::UpdateUserStats {
                    name: "symcts_cov".to_string(),
                    // value: UserStats::Ratio(num_cov_points as u64, state.metadata::<SyMCTSGlobalMetadata>().unwrap().coverage_point_info.len() as u64),
                    value: UserStats::Number(state.metadata::<SyMCTSGlobalMetadata>().unwrap().coverage_point_info.len() as u64),
                    phantom: PhantomData,
                },
            )?;
        }

        let global_meta = state.metadata_mut::<SyMCTSGlobalMetadata>().unwrap();

        global_meta.total_num_times_traced += 1;
        global_meta.last_traced_cov = Some((cov_summary, single_cov));

        if let Some((event, count)) = match exit_kind {
            libafl::executors::ExitKind::Crash => {
                global_meta.total_num_times_crashed += 1;
                Some(("crashes", global_meta.total_num_times_crashed))
            },
            libafl::executors::ExitKind::Timeout => {
                global_meta.total_num_times_timed_out += 1;
                Some(("timeouts", global_meta.total_num_times_timed_out))
            },
            _ => None
        } {
            manager.fire(
                state,
                Event::UpdateUserStats {
                    name: event.to_string(),
                    // value: UserStats::Ratio(num_cov_points as u64, state.metadata::<SyMCTSGlobalMetadata>().unwrap().coverage_point_info.len() as u64),
                    value: UserStats::Number(count as u64),
                    phantom: PhantomData,
                },
            )?;
        }
        return Ok(modified_global);
    }
}
