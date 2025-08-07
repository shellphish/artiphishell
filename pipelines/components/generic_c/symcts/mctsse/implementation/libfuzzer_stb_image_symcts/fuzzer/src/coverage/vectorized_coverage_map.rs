use std::simd::{SimdPartialEq, SimdOrd, SimdPartialOrd, Simd};
use bitvec::vec::BitVec;

use itertools::Itertools;
use serde::{Deserialize, Serialize, ser::{SerializeSeq, SerializeStruct}};
use super::loop_bucketing::get_bucketed_hitcount_inner;


pub type CounterType = u16;
pub const LANES: usize = 32;
pub const MIN_SINGLE_COUNT: CounterType = 0;
pub const MAX_SINGLE_COUNT: CounterType = 0xffff;


pub type VectorizedCounter = Simd<CounterType, LANES>;
pub type CounterCondMask = <VectorizedCounter as SimdPartialEq>::Mask;
pub const MIN_COUNT: VectorizedCounter = VectorizedCounter::from_array([MIN_SINGLE_COUNT; VectorizedCounter::LANES]);
pub const MAX_COUNT: VectorizedCounter = VectorizedCounter::from_array([MAX_SINGLE_COUNT; VectorizedCounter::LANES]);


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
    pub fn from_slice(slice: &[CounterType]) -> Self {
        let mut val = [MAX_SINGLE_COUNT; VectorizedCounter::LANES];
        for (i, v) in slice.iter().enumerate() {
            val[i] = *v;
        }
        MinimizingVectorizedCounter(VectorizedCounter::from_array(val))
    }

    #[inline(always)]
    pub fn is_better(&self, val: VectorizedCounter) -> CounterCondMask {
        let result = val.simd_lt(self.0);
        result
    }
    #[inline(always)]
    pub fn update_min(&mut self, value: VectorizedCounter) {
        self.0 = self.0.simd_min(value);
    }
    #[inline(always)]
    pub fn get(&self) -> &VectorizedCounter {
        &self.0
    }
    #[inline(always)]
    pub fn is_uninteresting(&self) -> bool {
        self.0.simd_eq(MAX_COUNT).all()
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
        Vec::<CounterType>::serialize(&self.0.to_array().to_vec(), serializer)
    }
}
impl<'de> Deserialize<'de> for MinimizingVectorizedCounter {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let vec = Vec::<CounterType>::deserialize(deserializer)?;
        assert!(vec.len() == VectorizedCounter::LANES);
        Ok(MinimizingVectorizedCounter::from_slice(&vec))
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
    pub fn from_slice(slice: &[CounterType]) -> MaximizingVectorizedCounter {
        let mut val = [MIN_SINGLE_COUNT; VectorizedCounter::LANES];
        for (i, v) in slice.iter().enumerate() {
            val[i] = *v;
        }
        MaximizingVectorizedCounter(VectorizedCounter::from_array(val))
    }
    #[inline(always)]
    pub fn is_better(&self, val: VectorizedCounter) -> CounterCondMask {
        val.simd_gt(self.0)
    }
    #[inline(always)]
    pub fn update_max(&mut self, value: VectorizedCounter) {
        self.0 = self.0.simd_max(value);
    }
    #[inline(always)]
    pub fn get(&self) -> &VectorizedCounter {
        &self.0
    }
    #[inline(always)]
    pub fn is_uninteresting(&self) -> bool {
        self.0.simd_eq(MIN_COUNT).all()
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
        Vec::<CounterType>::serialize(&self.0.to_array().to_vec(), serializer)
    }
}
impl<'de> Deserialize<'de> for MaximizingVectorizedCounter {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let vec = Vec::<CounterType>::deserialize(deserializer)?;
        assert!(vec.len() == VectorizedCounter::LANES);
        Ok(MaximizingVectorizedCounter::from_slice(&vec))
    }
}
#[derive(Clone, Debug, Default)]
pub struct VectorizedCoverage {
    pub input_length_exponent: usize,
    pub non_zero_bitmap: BitVec,
    pub map: Vec<VectorizedCounter>,
}
impl Serialize for VectorizedCoverage {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // serialize as a vector of u32s
        let vec = self
            .map
            .iter()
            .map(|x| x.to_array())
            .flatten()
            .collect::<Vec<_>>();
        let mut inner = serializer.serialize_struct("VectorizedCoverage", 2)?;
        inner.serialize_field("input_length", &self.input_length_exponent)?;
        inner.serialize_field("map", &vec)?;
        inner.end()
    }
}
impl<'de> Deserialize<'de> for VectorizedCoverage {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        panic!("Handle the new format!");
        // deserialize as a vector of u32s
        // let vec = Vec::<CounterType>::deserialize(deserializer)?;
        // assert!(vec.len() % VectorizedCounter::LANES == 0);

        // let map = vec
        //     .into_iter()
        //     .array_chunks::<{VectorizedCounter::LANES}>()
        //     .map(VectorizedCounter::from_array)
        //     .collect::<Vec<_>>();

        // Ok(Self {
        //     input_length_exponent: 0,
        //     non_zero_bitmap: BitVec::from_iter(map.iter().map(|&x| x != MIN_COUNT).collect_vec()),
        //     map
        // })
    }
}

impl VectorizedCoverage {
    pub fn from_shm_slice(input_length: usize, slice: &[u32]) -> Self {
        let mut non_zero_bitmap = BitVec::repeat(false, slice.len()/VectorizedCounter::LANES+1);
        let mut map = Vec::with_capacity(slice.len()/VectorizedCounter::LANES+1);
        for i in 0..(slice.len() + VectorizedCounter::LANES - 1) / VectorizedCounter::LANES {
            let start = i * VectorizedCounter::LANES;
            let mut val = [MIN_SINGLE_COUNT; VectorizedCounter::LANES];
            for j in 0..VectorizedCounter::LANES {
                let x = *slice.get(start + j).unwrap_or(&0);
                val[j] = if x == 0 {
                    0u32
                } else{
                    let hit_count = x & !(3 << 30);

                    let bucketed_count = get_bucketed_hitcount_inner(hit_count as usize) as u32;

                    let adjacent = (x & (2 << 30)) != 0;
                    let func_adjacent = (x & (1 << 30)) != 0;
                    match (bucketed_count, adjacent, func_adjacent) {
                        (0, false, true) => 1u32,
                        (0, true, _) => 2u32,
                        (x, _, _) => 2u32 + x,
                    }
                }
                .try_into().expect("should be able to convert to CounterType");
            }
            let counter = VectorizedCounter::from_array(val);
            non_zero_bitmap.set(i, counter.simd_ne(MIN_COUNT).any());
            map.push(counter);
        }
        Self {
            input_length_exponent: input_length.next_power_of_two().trailing_zeros() as usize,
            non_zero_bitmap,
            map,
        }
        // let missing_for_alignment = (VectorizedCounter::LANES - (slice.len() % VectorizedCounter::LANES)) % VectorizedCounter::LANES;
        // let bucketed_val_iter = slice
        //     .iter()
        //     .map(|&x| {
        //         if x == 0 {
        //             return 0u32;
        //         }
        //         let hit_count = x & !(3 << 30);

        //         let bucketed_count = get_bucketed_hitcount_inner(hit_count as usize) as u32;

        //         let adjacent = (x & (2 << 30)) != 0;
        //         let func_adjacent = (x & (1 << 30)) != 0;
        //         match (bucketed_count, adjacent, func_adjacent) {
        //             (0, false, true) => 1u32,
        //             (0, true, _) => 2u32,
        //             (x, _, _) => 2u32 + x,
        //         }
        //     })
        //     .chain(std::iter::repeat(0u32).take(missing_for_alignment));

        // let vectorized = bucketed_val_iter
        //     .array_chunks::<{VectorizedCounter::LANES}>()
        //     .map(VectorizedCounter::from_array)
        //     .collect::<Vec<_>>();
        // Self {
        //     non_zero_bitmap: BitVec::from_iter(vectorized.iter().map(|&x| x != MIN_COUNT).collect_vec()),
        //     map: vectorized,
        // }
    }
    pub fn num_vectored_entries(&self) -> usize {
        self.map.len()
    }
    pub fn coverage_map(&self) -> &[VectorizedCounter] {
        &self.map
    }
}