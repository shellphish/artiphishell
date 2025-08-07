use bitvec::vec::BitVec;
use itertools::Itertools;
use libafl::prelude::CorpusId;
use serde::{Deserialize, Serialize, ser::{SerializeMap, SerializeStruct}};
use std::{fmt::{Debug, Display}, cmp::max, ops::{BitOr, BitOrAssign}};

use super::{loop_bucketing::get_bucketed_hitcount_inner, InterestReason, SingleCoverage};

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct MinimizingU32(u32);
impl MinimizingU32 {
    pub fn new() -> Self {
        Self(u32::MAX)
    }
    pub fn new_with_val(val: u32) -> Self {
        Self(val)
    }
    #[inline(always)]
    pub fn is_better(&self, val: u32) -> bool {
        val < self.0
    }
    #[inline(always)]
    pub fn update_min(&mut self, value: u32) -> bool {
        if self.0 > value {
            self.0 = value;
            true
        } else {
            false
        }
    }
    #[inline(always)]
    pub fn get(&self) -> u32 {
        self.0
    }
    #[inline(always)]
    pub fn is_uninteresting(&self) -> bool {
        self.0 == u32::MAX
    }
}

impl Default for MinimizingU32 {
    fn default() -> Self {
        Self::new()
    }
}
impl From<u32> for MinimizingU32 {
    fn from(val: u32) -> Self {
        Self(val)
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct MaximizingU32(u32);
impl MaximizingU32 {
    pub fn new() -> Self {
        Self(0)
    }
    pub fn new_with_val(val: u32) -> Self {
        Self(val)
    }
    #[inline(always)]
    pub fn is_better(&self, val: u32) -> bool {
        val > self.0
    }
    #[inline(always)]
    pub fn update_max(&mut self, value: u32) -> bool {
        if self.0 < value {
            self.0 = value;
            true
        } else {
            false
        }
    }
    #[inline(always)]
    pub fn get(&self) -> u32 {
        self.0
    }
    #[inline(always)]
    pub fn is_uninteresting(&self) -> bool {
        self.0 == 0
    }
}
impl Default for MaximizingU32 {
    fn default() -> Self {
        Self::new()
    }
}
impl From<u32> for MaximizingU32 {
    fn from(val: u32) -> Self {
        Self(val)
    }
}

pub struct HitcountsDisplay<'a>(&'a [u32]);
impl<'a> Debug for HitcountsDisplay<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.0.iter().map(|x| format!("{:08b}", x))).finish()
    }
}

#[derive(Clone)]
pub struct CoverageMinMaxTracker {
    pub longest_input: (CorpusId, usize),
    pub present_bitmap: BitVec,
    pub map: Vec<(MinimizingU32, MaximizingU32)>,
    pub corpus: Vec<CorpusId>,
}

impl Serialize for CoverageMinMaxTracker {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let interesting_entries = self.interesting_entries().into_iter().enumerate().collect::<Vec<_>>();

        let mut object = serializer.serialize_struct("CoverageMinMaxTracker", 3)?;
        object.serialize_field("map_entries_len", &self.map.len())?;
        object.serialize_field("interesting_entries", &interesting_entries)?;
        object.serialize_field("corpus", &self.corpus)?;

        object.end()
    }
}
impl<'de> Deserialize<'de> for CoverageMinMaxTracker {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        panic!("Not implemented");
    }
}

impl Debug for CoverageMinMaxTracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CoverageMinMaxTracker")
            .field("map_entries", &self.map.len())
            .field("map_entries_interesting", &self.map.iter().filter(|(_min, _max)| (!_min.is_uninteresting() && !_max.is_uninteresting())).count())
            .field("corpus", &self.corpus)
            .finish()
    }
}

impl CoverageMinMaxTracker {

    pub fn create(initial_counts: &SingleCoverage, initial_corpus_id: CorpusId) -> Self {
        Self {
            longest_input: (initial_corpus_id, initial_counts.input_length),
            present_bitmap: initial_counts.non_zero_bitmap.clone(),
            map: initial_counts
                .map
                .iter()
                .map(|&x| (x.into(), x.into()))
                .collect_vec(),
            corpus: vec![initial_corpus_id],
        }
    }

    fn interesting_entries(&self) -> Vec<&(MinimizingU32, MaximizingU32)> {
        assert!(self.present_bitmap.len() == self.map.len());
        self.present_bitmap.iter_ones().map(|i| &self.map[i]).collect_vec()
    }

    pub fn is_interesting_for(&self, coverage: &SingleCoverage) -> Option<InterestReason> {
        assert!(coverage.num_vectored_entries() == self.map.len());

        if coverage.input_length > self.longest_input.1 {
            return Some(InterestReason::LongerInput {
                corpus_id: coverage.corpus_id,
                old: self.longest_input.1,
                new: coverage.input_length,
            });
        }

        let positions_to_consider = self.present_bitmap.clone() | &coverage.non_zero_bitmap;

        let res = positions_to_consider
            .iter_ones()
            .filter_map(|i| {
                let cov = coverage.map[i];
                let (min_ent, max_ent) = self.map.get(i).map(|x| (x.0, x.1)).unwrap_or_default();
                let minimizes = min_ent.is_better(cov);

                // fast path out ASAP if at all possible
                if minimizes {
                    return Some(InterestReason::Minimizes {
                        index: i,
                        old: min_ent.get(),
                        new: cov,
                    });
                }
                if cov == 0 { // if it doesn't minimize, 0 can never maximize either
                    return None;
                }

                let maximizes = max_ent.is_better(cov);
                if maximizes {
                    return Some(InterestReason::Maximizes {
                        index: i,
                        old: max_ent.get(),
                        new: cov,
                    });
                }
                return None;
            })
            .next();

        // if res.is_none() {
        //     panic!("Shouldn't be possible to get here: {:?} {:?}", self, coverage);
        // }
        res
    }
    pub fn add(&mut self, coverage: &SingleCoverage, value: CorpusId) {

        let mut was_novel = false;

        if coverage.input_length > self.longest_input.1 {
            self.longest_input = (value, coverage.input_length);
            was_novel = true;
        }
        assert!(self.present_bitmap.len() == self.map.len());
        assert!(self.map.len() == coverage.map.len());

        self.present_bitmap |= coverage.non_zero_bitmap.clone();

        for i in self.present_bitmap.iter_ones() {
            let coverage_val = coverage.map[i];
            let minimized = self.map[i].0.update_min(coverage_val);
            let maximized = self.map[i].1.update_max(coverage_val);
            was_novel = was_novel || minimized || maximized;
        }
        if was_novel {
            self.corpus.push(value);
        }
    }

    pub fn corpus(&self) -> &Vec<CorpusId> {
        &self.corpus
    }
}
