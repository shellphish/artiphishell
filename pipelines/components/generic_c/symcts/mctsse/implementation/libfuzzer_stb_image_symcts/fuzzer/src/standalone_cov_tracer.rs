use std::{time::{SystemTime, Duration}, path::{Path, PathBuf}, ops::{Not, BitAnd}};
use bitvec::vec::BitVec;
use libafl::prelude::*;
use libafl_bolts::{shmem::{StdShMemProvider, UnixShMemProvider, ShMemProvider, ShMem}, rands::StdRand, AsSlice, AsMutSlice};


#[derive(Clone, Debug, PartialEq)]
pub enum TraceResult {
    Compressed {
        hit_vec: BitVec,
        adjacent_vec: BitVec,
        func_adjacent_vec: BitVec,
    },
    Uncompressed {
        observer_map: Vec<u32>,
    },
}
impl Eq for TraceResult {

}
const MASK_HIT: u32 = !(3 << 30);
const MASK_ADJACENT: u32 = 2 << 30;
const MASK_FUNC_ADJACENT: u32 = 1 << 30;

impl TraceResult {
    pub fn num_hit(&self) -> usize {
        let result = match self {
            TraceResult::Compressed { hit_vec, .. } => hit_vec.count_ones(),
            TraceResult::Uncompressed { observer_map } => observer_map.iter().filter(|&&x| x & MASK_HIT != 0).count(),
        };
        log::debug!("num_hit: {}", result);
        result
    }
    pub fn num_adjacent(&self) -> usize {
        match self {
            TraceResult::Compressed { adjacent_vec, .. } => adjacent_vec.count_ones(),
            TraceResult::Uncompressed { observer_map } => observer_map.iter().filter(|&&x| x & MASK_ADJACENT != 0).count(),
        }
    }
    pub fn num_func_adjacent(&self) -> usize {
        match self {
            TraceResult::Compressed { func_adjacent_vec, .. } => func_adjacent_vec.count_ones(),
            TraceResult::Uncompressed { observer_map } => observer_map.iter().filter(|&&x| x & MASK_FUNC_ADJACENT != 0).count(),
        }
    }
    pub fn hit_vec(&self) -> &BitVec {
        match self {
            TraceResult::Compressed { hit_vec, .. } => hit_vec,
            TraceResult::Uncompressed { .. } => panic!("Cannot get hit_vec from uncompressed trace result"),
        }
    }
    pub fn adjacent_vec(&self) -> &BitVec {
        match self {
            TraceResult::Compressed { adjacent_vec, .. } => adjacent_vec,
            TraceResult::Uncompressed { .. } => panic!("Cannot get adjacent_vec from uncompressed trace result"),
        }
    }
    pub fn func_adjacent_vec(&self) -> &BitVec {
        match self {
            TraceResult::Compressed { func_adjacent_vec, .. } => func_adjacent_vec,
            TraceResult::Uncompressed { .. } => panic!("Cannot get func_adjacent_vec from uncompressed trace result"),
        }
    }

    fn for_observer_map(observer_map: &[u32], compressed: bool) -> TraceResult {
        if !compressed {
            return TraceResult::Uncompressed {
                observer_map: observer_map.to_vec(),
            };
        }
        let len = observer_map.len();
        let (mut hit_vec, mut adjacent_vec, mut func_adjacent_vec) = (
            BitVec::repeat(false, len),
            BitVec::repeat(false, len),
            BitVec::repeat(false, len)
        );
        for (i, count) in observer_map.iter().enumerate() {
            let val = *count;
            if val == 0 {
                continue;
            }
            // println!("i: {}, val: {:x}", i, val);
            let count = val & !(3 << 30);
            let adjacent = val & (2 << 30) != 0;
            let func_adjacent = val & (1 << 30) != 0;
            if count != 0 {
                hit_vec.set(i, true);
            }
            if adjacent {
                adjacent_vec.set(i, true);
            }
            if func_adjacent {
                func_adjacent_vec.set(i, true);
            }
        }
        TraceResult::Compressed {
            hit_vec,
            adjacent_vec,
            func_adjacent_vec,
        }
    }
    pub fn is_compressed(&self) -> bool {
        match self {
            TraceResult::Compressed { .. } => true,
            TraceResult::Uncompressed { .. } => false,
        }
    }
    pub fn is_uncompressed(&self) -> bool {
        !self.is_compressed()
    }
    pub fn merge(&mut self, other: &TraceResult) -> (BitVec, BitVec, BitVec) {
        assert!(self.is_compressed());
        match (self, other) {
            (TraceResult::Compressed { hit_vec, adjacent_vec, func_adjacent_vec }, TraceResult::Compressed { hit_vec: other_hit_vec, adjacent_vec: other_adjacent_vec, func_adjacent_vec: other_func_adjacent_vec }) => {
                let novel_hit = hit_vec.clone().not().bitand(other_hit_vec);
                let novel_adjacent = adjacent_vec.clone().not().bitand(other_adjacent_vec);
                let novel_func_adjacent = func_adjacent_vec.clone().not().bitand(other_func_adjacent_vec);
                *hit_vec |= other_hit_vec;
                *adjacent_vec |= other_adjacent_vec;
                *func_adjacent_vec |= other_func_adjacent_vec;
                (novel_hit, novel_adjacent, novel_func_adjacent)
            },
            (self_ @ TraceResult::Compressed { .. }, TraceResult::Uncompressed { observer_map }) => {
                return self_.merge(&TraceResult::for_observer_map(observer_map, true));
            }
            _ => panic!("Cannot merge uncompressed trace results"),
        }
    }
}

pub struct TracedInput {
    pub path: PathBuf,
    pub timestamp: SystemTime,
    pub result: TraceResult,
    pub exit_kind: ExitKind,
}

type MyOT<'shmem> = (StdMapObserver<'shmem, u32, false>, ());
type MyState = StdState<BytesInput, InMemoryCorpus::<BytesInput>, StdRand, InMemoryCorpus<BytesInput>>;
pub struct Tracer<'shmem> {
    coverage_executor: TimeoutForkserverExecutor<ForkserverExecutor<MyOT<'shmem>, MyState, UnixShMemProvider>>,
}
impl<'shmem> Tracer<'shmem> {
    pub fn create(trace_commandline: Vec<String>) -> Result<Self, libafl::Error> {

        let mut shmem_provider = StdShMemProvider::new().unwrap();

        const MAP_SIZE: usize = 65536 * 16;
        std::env::set_var("AFL_MAP_SIZE", MAP_SIZE.to_string());
        let mut afl_shm = shmem_provider
            .new_shmem(MAP_SIZE)
            .unwrap();

        afl_shm.write_to_env("__AFL_SHM_ID").unwrap();
        let afl_shm_id = afl_shm.id().to_string();

        let slice_of_u8s = afl_shm.as_mut_slice();
        // convert slice to slice of u32s
        let slice_of_u32s = unsafe {
            std::slice::from_raw_parts_mut(
                slice_of_u8s.as_mut_ptr() as *mut u32,
                slice_of_u8s.len() / std::mem::size_of::<u32>(),
            )
        };

        let afl_map_observer = unsafe {
            StdMapObserver::<u32, false>::new("afl_map", slice_of_u32s)
        };

        let coverage_executor = ForkserverExecutor::builder()
            .program(&trace_commandline[0])
            .debug_child(true)
            .shmem_provider(&mut shmem_provider)
            .is_persistent(true)
            .env("__AFL_SHM_ID", afl_shm_id)
            .env("__AFL_OUT_DIR", "/tmp/afl_out")
            .parse_afl_cmdline(&trace_commandline[1..])
            .build_dynamic_map::<StdMapObserver<u32, false>, (), StdState<BytesInput, InMemoryCorpus::<BytesInput>, StdRand, InMemoryCorpus<BytesInput>>>(afl_map_observer, ())
            .expect("Could not build coverage forkserver executor??");

        let coverage_executor = TimeoutForkserverExecutor::new(
            coverage_executor, Duration::from_secs(1)
        ).expect("Could not build timeout coverage forkserver executor??");

        Ok(Tracer {
            coverage_executor,
        })
    }

    pub fn trace_input(&mut self, path: &Path, timestamp: SystemTime, compress_map: bool) -> Result<TracedInput, libafl::Error> {
        let input = BytesInput::from_file(path)?;
        self.coverage_executor.observers_mut().0.reset_map()?;
        let exit_kind = self.coverage_executor.execute_input(&input)?;
        let observer_map = self.coverage_executor.observers().0.as_slice();
        let result = TraceResult::for_observer_map(observer_map, compress_map);
        Ok(TracedInput {
            path: path.to_owned(),
            timestamp,
            result,
            exit_kind
        })
    }
}