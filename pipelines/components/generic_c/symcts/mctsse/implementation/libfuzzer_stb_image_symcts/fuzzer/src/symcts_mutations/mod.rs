use concolic_trace_interpretation::ConstraintKey;
use libafl::{observers::concolic::{Location, SymExprRef}, prelude::CorpusId};
use libafl_bolts::impl_serdeany;
use serde::{Deserialize, Serialize};
use crate::metadata::solve_stats::SolveLocation;


#[derive(Debug, Clone, Copy, Hash, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum MutationKind {
    Original,
    SageSolving,
    SymCCSamplingPathPreserving,
    SymCCSampling,
    WeakSolving,
    OptimisticSolving,
}
impl_serdeany!(MutationKind);

#[derive(Debug, Clone, Hash, Serialize, Deserialize)]
pub struct MutationSource {
    pub kind: MutationKind,
    pub corpus_id: CorpusId,
    pub source_filename: Option<String>,
    pub constraint_key: ConstraintKey,
    pub location: SolveLocation,
    pub num_path_constraints_prior: usize,
    pub generational_would_have_skipped: bool,
    pub input_mutation_time_so_far: u128,
    pub input_mutation_time_total: u128,
    pub own_solve_time: u128,
    pub current_backoff: u128,
}
impl_serdeany!(MutationSource);

#[derive(Debug, Default, Clone, Hash, Serialize, Deserialize)]
pub struct MutationResultMetadata {
    pub num_times_scheduled_for_mutation: usize,
}
impl_serdeany!(MutationResultMetadata);

#[derive(Debug)]
pub struct Mutation {
    pub source: MutationSource,
    pub changes: Vec<(usize, u8)>,
}

pub trait SyMCTSConcolicMutation {
    fn new(expressions: &Vec<SymExprRef>, input: &Vec<u8>) -> Self;

    fn handle_path_constraint(&mut self, expr_id: SymExprRef, taken: bool, location: Location) -> bool;
    fn handle_pointer_concretization(&mut self, expr_id: SymExprRef, value: u64, location: Location) -> bool;
    fn handle_size_concretization(&mut self, expr_id: SymExprRef, value: u64, location: Location) -> bool;

    fn finalize(&mut self) -> Vec<Mutation>;
}

