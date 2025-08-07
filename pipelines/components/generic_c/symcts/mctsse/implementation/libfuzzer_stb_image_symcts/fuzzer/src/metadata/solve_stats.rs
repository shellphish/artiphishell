//! Map feedback, maximizing or minimizing maps, for example the afl-style map observer.
use core::fmt::Debug;
use std::fmt::{Display, Formatter};
use libafl::observers::concolic::Location;
use libafl_bolts::impl_serdeany;
use serde::ser::SerializeMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct SolveLocation {
    last: Location,
    cur: Location,
    // the nth constraint produced at this point
    // (e.g. concretization: 0 => lt, 1 => gt, 2 => eq, @branch: 0 => not taken, 1 => taken)
    index: usize,
}
impl Display for SolveLocation {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:x?}:{:x?}:{}", self.last, self.cur, self.index)
    }
}
impl SolveLocation {
    pub fn new(last: Location, cur: Location, index: usize) -> Self {
        Self { last, cur, index }
    }
}

#[derive(Default, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SolveLocationInfo {
    pub num_inputs_produced: usize,
    pub num_successful_mutations: usize,
    pub num_times_seen: usize,
    pub num_times_seen_symbolic: usize,
    pub num_times_seen_feasible: usize,
    pub num_times_seen_unknown: usize,
    pub num_times_seen_unknown_optimistic: usize,
    pub num_times_seen_unknown_weak: usize,
    pub num_times_seen_unknown_sage: usize,
    pub num_times_seen_unknown_quicksampler: usize,
    pub num_times_seen_since_last_successful_mutation: usize,
    pub num_times_seen_feasible_since_last_successful_mutation: usize,
    pub num_inputs_produced_since_last_successful_mutation: usize,
    pub min_solve_time_optimistic: Option<u128>,
    pub min_solve_time_weak: Option<u128>,
    pub min_solve_time_sage: Option<u128>,
    pub min_solve_time_quicksampler: Option<u128>,
    pub max_solve_time_optimistic: Option<u128>,
    pub max_solve_time_weak: Option<u128>,
    pub max_solve_time_sage: Option<u128>,
    pub max_solve_time_quicksampler: Option<u128>,
    pub total_time_solved_for: u128,
    pub total_time_solved_for_optimistic: u128,
    pub total_time_solved_for_weak: u128,
    pub total_time_solved_for_sage: u128,
    pub total_time_solved_for_quicksampler: u128,
}
impl_serdeany!(SolveLocationInfo);


// TODO maybe use bignums instead of just usize, for now use `checked_add` to see if necessary
#[derive(Default, Debug, Deserialize, Clone)]
pub struct SymbolicSolveStats {
    pub stats: HashMap<SolveLocation, SolveLocationInfo>,
}
impl_serdeany!(SymbolicSolveStats);

impl Serialize for SymbolicSolveStats {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer {
            let mut map = serializer.serialize_map(Some(self.stats.len()))?;
            for (k, v) in &self.stats {
                map.serialize_entry(&format!("{:?}", k), v)?;
            }
            map.end()
    }
}
