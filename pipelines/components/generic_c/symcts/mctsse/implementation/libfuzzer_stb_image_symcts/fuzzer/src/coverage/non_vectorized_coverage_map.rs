use std::simd::{u32x16, SimdPartialEq, SimdOrd, SimdPartialOrd};
use bitvec::vec::BitVec;

use itertools::Itertools;
use serde::{Deserialize, Serialize, ser::SerializeSeq};
use super::loop_bucketing::get_bucketed_hitcount_inner;


pub type VectorizedCounter = u32;
pub type CounterCondMask = bool;
pub const MIN_COUNT: VectorizedCounter = 0;
pub const MAX_COUNT: VectorizedCounter = 0xffffffff;


#[derive(Clone, Copy, Debug)]
pub struct MinimizingVectorizedCounter(VectorizedCounter);
impl From<VectorizedCounter> for MinimizingVectorizedCounter {
    fn from(val: VectorizedCounter) -> Self {
        Self(val)
    }
}
impl MinimizingVectorizedCounter {
    pub fn new() -> Self {
        Self(MAX_COUNT)
    }
    #[inline(always)]
    pub fn is_better(&self, val: VectorizedCounter) -> CounterCondMask {
        let result = val < self.0;
        result
    }
    #[inline(always)]
    pub fn update_min(&mut self, value: VectorizedCounter) {
        self.0 = std::cmp::min(self.0, value)
    }
    #[inline(always)]
    pub fn get(&self) -> &VectorizedCounter {
        &self.0
    }
    #[inline(always)]
    pub fn is_uninteresting(&self) -> bool {
        self.0 == MAX_COUNT
    }
    #[inline(always)]
    pub fn from_slice(&self, slice: &[u32]) -> MinimizingVectorizedCounter {
        MinimizingVectorizedCounter(slice.get(0).copied().unwrap_or(MAX_COUNT))
    }
}

impl Default for MinimizingVectorizedCounter {
    fn default() -> Self {
        Self::new()
    }
}


impl Serialize for MinimizingVectorizedCounter {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        u32::serialize(&self.0, serializer)
    }
}
impl<'de> Deserialize<'de> for MinimizingVectorizedCounter {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let val = u32::deserialize(deserializer)?;
        Ok(MinimizingVectorizedCounter(val))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct MaximizingVectorizedCounter(VectorizedCounter);

impl From<VectorizedCounter> for MaximizingVectorizedCounter {
    fn from(val: VectorizedCounter) -> Self {
        Self(val)
    }
}

impl MaximizingVectorizedCounter {
    #[inline(always)]
    pub fn new() -> Self {
        Self(MIN_COUNT)
    }
    #[inline(always)]
    pub fn is_better(&self, val: VectorizedCounter) -> CounterCondMask {
        val > self.0
    }
    #[inline(always)]
    pub fn update_max(&mut self, value: VectorizedCounter) {
        self.0 = std::cmp::max(self.0, value);
    }
    #[inline(always)]
    pub fn get(&self) -> &VectorizedCounter {
        &self.0
    }
    #[inline(always)]
    pub fn is_uninteresting(&self) -> bool {
        self.0 == MIN_COUNT
    }
    #[inline(always)]
    pub fn from_slice(&self, slice: &[u32]) -> MaximizingVectorizedCounter {
        MaximizingVectorizedCounter(slice.get(0).copied().unwrap_or(MIN_COUNT))
    }
}

impl Default for MaximizingVectorizedCounter {
    fn default() -> Self {
        Self::new()
    }
}

impl Serialize for MaximizingVectorizedCounter {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        u32::serialize(&self.0, serializer)
    }
}
impl<'de> Deserialize<'de> for MaximizingVectorizedCounter {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let val = u32::deserialize(deserializer)?;
        Ok(MaximizingVectorizedCounter(val))
    }
}
#[derive(Clone, Debug, Default)]
pub struct NonVectorizedCoverage {
    pub input_length: usize,
    pub non_zero_bitmap: BitVec,
    pub map: Vec<VectorizedCounter>,
}
impl Serialize for NonVectorizedCoverage {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        <[u32]>::serialize(&self.map, serializer)
    }
}
impl<'de> Deserialize<'de> for NonVectorizedCoverage {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let map = Vec::<u32>::deserialize(deserializer)?;
        let non_zero_bitmap = BitVec::from_iter(map.iter().map(|&x| x != 0));
        Ok(NonVectorizedCoverage {
            non_zero_bitmap,
            map,
        })
    }
}

impl NonVectorizedCoverage {
    pub fn from_shm_slice(input_length: usize, slice: &[u32]) -> Self {
        let bucketed_val_iter = slice
            .iter()
            .map(|&x| {
                if x == 0 {
                    return 0u32;
                }
                let hit_count = x & !(3 << 30);

                let bucketed_count = get_bucketed_hitcount_inner(hit_count as usize) as u32;

                let adjacent = (x & (2 << 30)) != 0;
                let func_adjacent = (x & (1 << 30)) != 0;
                match (bucketed_count, adjacent, func_adjacent) {
                    (0, false, true) => 1u32,
                    (0, true, _) => 2u32,
                    (x, _, _) => 2u32 + x,
                }
            });

        let vectorized = bucketed_val_iter
            .collect::<Vec<_>>();
        Self {
            input_length,
            non_zero_bitmap: BitVec::from_iter(vectorized.iter().map(|&x| x != MIN_COUNT).collect_vec()),
            map: vectorized,
        }
    }
    pub fn num_vectored_entries(&self) -> usize {
        self.map.len()
    }
    pub fn coverage_map(&self) -> &[VectorizedCounter] {
        &self.map
    }
}