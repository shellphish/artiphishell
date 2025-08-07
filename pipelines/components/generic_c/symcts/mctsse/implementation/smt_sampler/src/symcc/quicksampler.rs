use std::collections::{HashSet, HashMap};
use std::time::Instant;

use bitvec::vec::BitVec;
use itertools::Itertools;
use log::warn;
use rand::{thread_rng, seq::SliceRandom};
use sorted_vec::SortedSet;
use z3::{SatResult, Context, Optimize};
use z3::ast::{Ast, BV, Bool};

#[cfg(feature = "z3jit_support")]
use z3jit::jit_constraint::{CodeGen, JitContext};

#[cfg(not(feature = "z3jit_support"))]
use std::marker::PhantomData;

#[cfg(not(feature = "z3jit_support"))]
type JitContext = ();

#[cfg(not(feature = "z3jit_support"))]
struct CodeGen<'z3_ctx, 'jit_ctx> {
    phantom_jit_ctx : PhantomData<&'jit_ctx ()>,
    phantom_z3_ctx: PhantomData<&'z3_ctx ()>
}


use crate::z3_util::ast_visitor::consts;
use crate::z3_util::z3_timed::TimedSolver;
use crate::GUARD_PREFIX;
use super::model::SymCCModel;
use super::mutation::SymCCMutation;
use super::input_vars::symcc_name_to_byte_idx;

#[derive(Debug, Eq, PartialEq, PartialOrd, Ord, Clone, Copy, Hash)]
pub struct PrimitiveMutationLocation {
    byte_idx: usize,
    bit_idx: usize,
}
#[derive(Debug, Eq, PartialEq, PartialOrd, Ord, Clone, Hash)]
pub enum MutationFailed<'z3_ctx> {
    SolverUnsat { core: Vec<Bool<'z3_ctx>>, constraints_smt2: Option<String> },
    SolverUnknown { reason: Option<String>, constraints_smt2: Option<String> }
}


#[derive(Debug)]
struct StateCacheEntry<'z3_ctx, 'jit_ctx> {
    // this must include the set of constrained bytes in the next level down of the stack as well, but might have
    // different (larger) size than previous layer due to reintroduced
    constrained_bytes: BitVec,
    // constraint at this level
    constraint: Bool<'z3_ctx>,
    // jit of the current constraint
    jit: CodeGen<'jit_ctx, 'z3_ctx>,

    // caching valid solved-for mutations (don't cache ones a simple check can rediscover, should be faster I think?)
    // might have to reconsider as well if that turns out not to be true
    known_impossible_mutations: HashMap<PrimitiveMutationLocation, MutationFailed<'z3_ctx>>,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SymCCSamplerStatistics {
    queries_trivial: usize,
    queries_unsat_cache_hit: usize,
    queries_solved_for: usize,
    num_queries: usize,


}

#[derive(Debug)]
pub struct SymCCSamplerState<'z3_ctx, 'jit_ctx> {
    z3_ctx: &'z3_ctx z3::Context,
    jit_ctx: &'jit_ctx JitContext,

    variables: Vec<BV<'z3_ctx>>,
    optimizer: Optimize<'z3_ctx>,

    stack: Vec<StateCacheEntry<'z3_ctx, 'jit_ctx>>,

    stats: SymCCSamplerStatistics,

    #[cfg(feature="primitive_mutation_caching")]
    optimistic_non_trivial_mutation_cache: HashMap<PrimitiveMutationLocation, SymCCMutation>,
}
impl<'z3_ctx, 'jit_ctx> SymCCSamplerState<'z3_ctx, 'jit_ctx> {
    pub fn new(z3_ctx: &'z3_ctx z3::Context, jit_ctx: &'jit_ctx JitContext) -> Self {
        let optimizer = Optimize::new(z3_ctx);
        let base_element = StateCacheEntry {
            constrained_bytes: BitVec::new(),
            constraint: Bool::from_bool(z3_ctx, true),
            jit: CodeGen::new(jit_ctx, vec![Bool::from_bool(z3_ctx, true)], "jitted_constraint_true").expect("The codegen should always work!"),
            known_impossible_mutations: HashMap::new()
        };
        Self {
            z3_ctx,
            jit_ctx,

            variables: vec![],
            optimizer,
            stack: vec![base_element],
            stats: Default::default(),

            #[cfg(feature="primitive_mutation_caching")]
            optimistic_non_trivial_mutation_cache: HashMap::new(),
        }
    }
    pub fn variables(&self) -> &Vec<BV<'z3_ctx>> {
        &self.variables
    }
    pub fn ensure_byte_vars_exist_upto(&mut self, num_total: usize) {
        if num_total <= self.variables.len() {
            return;
        }
        let num_new = num_total - self.variables.len();
        assert!(num_new > 0);
        let new_vars_iter = (self.variables.len()..num_total)
            .map(|i| {
                BV::new_const(self.z3_ctx, format!("k!{}", i * 10), 8)
            });
        self.variables.extend(new_vars_iter);

        self.stack.last_mut().unwrap().constrained_bytes.resize(num_total, false);
    }
    pub fn push_new_constraint(&mut self, new_constraint: Bool<'z3_ctx>) -> Result<(), MutationFailed> {
        self.optimizer.push();
        self.optimizer.assert(&new_constraint);
        match self.optimizer.timed_check_assumptions(&[]) {
            SatResult::Sat => Ok(()),
            SatResult::Unknown => {
                let reason = self.optimizer.get_reason_unknown();
                self.optimizer.pop();
                // Err( MutationFailed::SolverUnknown { reason, constraints_smt2: Some(self.optimizer.to_string()) } )
                Err( MutationFailed::SolverUnknown { reason, constraints_smt2: None } )
            },
            SatResult::Unsat => {
                let unsat_core = self.optimizer.get_unsat_core();
                self.optimizer.pop();
                // self.optimizer.pop();
                // Err( MutationFailed::SolverUnsat { core: unsat_core, constraints_smt2: Some(self.optimizer.to_string()) })
                Err( MutationFailed::SolverUnsat { core: unsat_core, constraints_smt2: None })
            }
        }?;

        let tos = self.stack.last().unwrap();
        let known_impossible_mutations = tos.known_impossible_mutations.clone();

        let mut constrained_bytes = tos.constrained_bytes.clone();
        for var in consts(&new_constraint.clone().into()) {
            let byte_idx = symcc_name_to_byte_idx(&var.decl().name());
            constrained_bytes.set(byte_idx, true);
        }
        let constraints = self.stack.iter().map(|e| &e.constraint).cloned().chain([new_constraint.clone()]).collect_vec();
        let jit = CodeGen::new(
            self.jit_ctx,
            constraints,
            &format!("jitted_constraints_{}", self.stack.len())
        ).expect("The codegen should always work!");
        self.stack.push(StateCacheEntry {
            constrained_bytes,
            constraint: new_constraint,
            jit,
            known_impossible_mutations,
        });
        Ok(())
    }

    pub fn pop_constraint(&mut self, expected_constraint: Bool<'z3_ctx>) {
        let last = self.stack.pop().expect("You can't pop off an empty stack, you dumbass.");
        assert!(last.constraint == expected_constraint);
        self.optimizer.pop();
    }

    fn with_model_specialization<'state, 'model> (
        &'state mut self,
        model: &'model SymCCModel<'z3_ctx>
    ) -> ModelSpecializedStateGuard<'z3_ctx, 'jit_ctx, 'state, 'model> {
        ModelSpecializedStateGuard::acquire(self, model)
    }

    pub fn is_model_valid(&self, model: &SymCCModel<'z3_ctx>) -> bool {
        let byte_slice = model.concrete_bytes();
        self.is_bytes_valid_model(byte_slice)
    }
    pub fn is_bytes_valid_model(&self, bytes: &[u8]) -> bool {
        // we've switched to recompiling all constraints each time, so only check last entry
        self.stack.last().unwrap().jit.evaluate_input(bytes)
        // for entry in self.stack.iter() { // no need to reverse the stack here, we have to check all of them anyways
        //     if !entry.jit.evaluate_input(bytes) {
        //         return false;
        //     }
        // }
        // return true;
    }

    pub fn get_constrained_mutation_locations(&self) -> Vec<PrimitiveMutationLocation> {
        let stack_top = self.stack.last().expect("Cannot operate on an empty stack, somehow you managed to misalign pushes and pops.");
        let mut mutation_locs = vec![];
        for (byte_idx, is_byte_constrained) in stack_top.constrained_bytes.iter().enumerate() {
            if !*is_byte_constrained {
                continue;
            }
            // okay, so bytes[i] is constrained and we need its mutations
            for bit_idx in 0..8 {
                mutation_locs.push(PrimitiveMutationLocation { byte_idx, bit_idx });
            }
        }
        mutation_locs
    }
}

#[derive(Debug)]
struct ModelSpecializedStateGuard<'z3_ctx, 'jit_ctx, 'state, 'model> {
    soft_asserted_model: &'model SymCCModel<'z3_ctx>,
    model_bytes_working_copy: Vec<u8>,
    state: &'state mut SymCCSamplerState<'z3_ctx, 'jit_ctx>,
}
impl<'z3_ctx, 'jit_ctx, 'state, 'model> Drop for ModelSpecializedStateGuard<'z3_ctx, 'jit_ctx, 'state, 'model> {
    fn drop(&mut self) {
        // cleanup model-specific shit
        self.state.optimizer.pop()
    }
}
impl <'z3_ctx, 'jit_ctx, 'state, 'model> ModelSpecializedStateGuard<'z3_ctx, 'jit_ctx, 'state, 'model> {
    pub fn acquire(state: &'state mut SymCCSamplerState<'z3_ctx, 'jit_ctx>, model: &'model SymCCModel<'z3_ctx>) -> Self {
        let model_bytes_working_copy = model.concrete_bytes().to_vec();
        state.optimizer.push();
        for (i, var_ast) in model.byte_variables().iter().enumerate() {
            if model.is_byte_constrained(i) {
                let val_ast = BV::from_u64(state.z3_ctx, model_bytes_working_copy[i] as u64, 8);
                state.optimizer.assert_soft(&var_ast._eq(&val_ast), 1u64, None);
            }
        }

        // log::info!("Acquired model-specific solver instance with model {:?}", model_bytes_working_copy);
        assert_eq!(model_bytes_working_copy, model.concrete_bytes());
        Self {
            soft_asserted_model: model,
            model_bytes_working_copy,
            state,
        }
    }
    fn is_primitive_mutation_trivial(&mut self, loc: PrimitiveMutationLocation) -> bool {
        assert_eq!(self.model_bytes_working_copy, self.soft_asserted_model.concrete_bytes());
        self.model_bytes_working_copy[loc.byte_idx] ^= 1 << loc.bit_idx;
        let res = self.state.is_bytes_valid_model(&self.model_bytes_working_copy);
        self.model_bytes_working_copy[loc.byte_idx] ^= 1 << loc.bit_idx;
        assert_eq!(self.model_bytes_working_copy, self.soft_asserted_model.concrete_bytes());
        res
    }

    #[cfg(feature="primitive_mutation_caching")]
    fn get_cached_primitive_mutation(&mut self, loc: PrimitiveMutationLocation) -> Option<SymCCMutation> {
        if let Some(mutation) = self.state.optimistic_non_trivial_mutation_cache.get(&loc) {
            assert_eq!(self.model_bytes_working_copy, self.soft_asserted_model.concrete_bytes());
            mutation.apply_to_bytes(&mut self.model_bytes_working_copy);
            let valid_mutation = self.state.is_bytes_valid_model(&self.model_bytes_working_copy);
            mutation.undo_to_bytes(&mut self.model_bytes_working_copy); // undo the mutation
            assert!(self.model_bytes_working_copy == self.soft_asserted_model.concrete_bytes()); // can't hurt to make sure
            if valid_mutation {
                return Some(mutation.clone());
            }
            else {
                log::info!("Cached mutation for {:?} was invalid", loc);
            }
        }
        else {
            log::info!("Cache miss for {:?}", loc);
            // self.print_mutation_cache_state();
        }
        // not trivial, and no cached valid mutations available
        // TODO: consider checking if any of the other cached mutations flips this bit to avoid having to solve?
        return None;
    }
    #[cfg(feature="primitive_mutation_caching")]
    pub fn print_mutation_cache_state(&self) {
        log::info!("Optimistic mutation cache: [{} entries]", self.state.optimistic_non_trivial_mutation_cache.len());
        for loc in self.state.optimistic_non_trivial_mutation_cache.keys().sorted() {
            log::info!("\t{:?}", loc);
        }
        let last = self.state.stack.last().unwrap();
        log::info!("Known unsat cache: [{} entries]", last.known_impossible_mutations.len());
        for loc in last.known_impossible_mutations.iter().sorted() {
            log::info!("\t{:?} (impossible)", loc);
        }
    }
    pub fn solve_for_primitive_mutation(&self, loc: PrimitiveMutationLocation) -> Result<SymCCMutation, MutationFailed<'z3_ctx>> {
        let z3_ctx = self.soft_asserted_model.ctx;

        let (byte_idx, bit_idx) = (loc.byte_idx, loc.bit_idx);
        let flip_assumption_var = Bool::new_const(z3_ctx, format!("{GUARD_PREFIX}bitflip_{byte_idx}:{bit_idx}"));
        let bitval = self.soft_asserted_model.get_bit_val(loc.byte_idx, loc.bit_idx);

        let expected = BV::from_u64(z3_ctx,if bitval {0} else {1}, 1);
        let bit_idx = bit_idx.try_into().unwrap();
        let cst = flip_assumption_var.implies(
            &self.soft_asserted_model.byte_variables()[byte_idx].extract(
                bit_idx,
                bit_idx
            )
            ._eq(&expected)
        );
        self.state.optimizer.assert(&cst);

        let result = match self.state.optimizer.timed_check_assumptions(&[&flip_assumption_var]) {
            SatResult::Unknown => {
                Err(MutationFailed::SolverUnknown {
                    reason: self.state.optimizer.get_reason_unknown(),
                    // constraints_smt2: Some(self.state.optimizer.to_string())
                    constraints_smt2: None,
                })
            },
            SatResult::Unsat => {
                Err(MutationFailed::SolverUnsat {
                    core: self.state.optimizer.get_unsat_core(),
                    // constraints_smt2: Some(self.state.optimizer.to_string())
                    constraints_smt2: None,
                })
            },
            SatResult::Sat => {
                let cur_z3_model = self.state.optimizer.get_model()
                    .or_else(|| panic!("We expect a model for sat results??? {:?}", self.state.optimizer))
                    .unwrap();
                let vars_copy = self.soft_asserted_model.byte_variables().iter().cloned().collect::<Vec<_>>();
                let cur_model = SymCCModel::from_model(&cur_z3_model, &vars_copy[..]);

                // println!("Model for different {:?}#{}: [{:?}]", &var, bit_to_flip, cur_model);
                let mutation = cur_model.minimal_mutation(&self.soft_asserted_model);
                // println!("primitive mutation {:?}", mutation);
                Ok(mutation)
            }
        };
        result
    }


    pub fn get_primitive_mutation(&mut self, loc: PrimitiveMutationLocation) -> Result<SymCCMutation, MutationFailed<'z3_ctx>> {
        self.state.stats.num_queries += 1;
        #[cfg(feature="known_unsat_caching")]
        {
            let top = self.state.stack.last().unwrap();
            if let Some(reason) = top.known_impossible_mutations.get(&loc) {
                // assert!(self.solve_for_primitive_mutation(loc).is_err());
                self.state.stats.queries_unsat_cache_hit += 1;
                return Err(reason.clone())
            }
        }

        if self.is_primitive_mutation_trivial(loc) {
            let mutation = SymCCMutation::single_bit(self.model_bytes_working_copy.len(), loc.byte_idx, loc.bit_idx);
            #[cfg(feature="trivial_primitive_mutation_caching")]
            self.state.stack.last_mut().unwrap().optimistic_non_trivial_mutation_cache.insert(loc, mutation.clone());
            self.state.stats.queries_trivial += 1;
            return Ok(mutation);
        }

        #[cfg(feature="primitive_mutation_caching")]
        if let Some(mutation) = self.get_cached_primitive_mutation(loc) {
            log::info!("### Primitive mutation cache hit for {:?}", loc);
            self.state.stats.queries_optimistic_cache_hit += 1;
            return Ok(mutation);
        }

        self.state.stats.queries_solved_for += 1;

        let result = self.solve_for_primitive_mutation(loc);

        let last_mut = self.state.stack.last_mut().unwrap();
        match &result {
            #[cfg(feature="primitive_mutation_caching")]
            Ok(mutation) => {
                self.state.optimistic_non_trivial_mutation_cache.insert(loc, mutation.clone());
            }
            Err(x @ MutationFailed::SolverUnsat { .. }) => {
                #[cfg(feature="known_unsat_caching")]
                last_mut.known_impossible_mutations.insert(loc, x.clone());
            }
            _ => {} // in the unknown case don't do anything, this might actually be simplified by further constraints later
        }
        // println!("get_primitive_mutation({:?}) = {:?}", loc, result);
        result

        // not trivial, and no cached valid mutations available, ask optimizer for answer!
        // we've already asserted the soft model equality guaranteeing that the mutation will be minimal

    }
}

#[derive(Debug)]
pub struct SymCCSampler<'z3_ctx, 'jit_ctx> {
    _ctx: &'z3_ctx Context,
    state: SymCCSamplerState<'z3_ctx, 'jit_ctx>
}



impl<'z3_ctx, 'jit_ctx> SymCCSampler<'z3_ctx, 'jit_ctx> {
    pub fn new(
            z3_ctx: &'z3_ctx Context,
            jit_ctx: &'jit_ctx JitContext,
        ) -> SymCCSampler<'z3_ctx, 'jit_ctx>
    {
        let state = SymCCSamplerState::new(z3_ctx, jit_ctx);
        SymCCSampler {
            _ctx: z3_ctx,
            state
        }
    }

    pub fn variables(&self) -> &[BV<'z3_ctx>] {
        &self.state.variables
    }

    pub fn ensure_byte_vars_exist_upto(&mut self, num_vars_total: usize) {
        self.state.ensure_byte_vars_exist_upto(num_vars_total);
    }

    pub fn get_var_for_byte(&mut self, index: usize) -> BV<'z3_ctx> {
        self.state.ensure_byte_vars_exist_upto(index + 1);
        self.state.variables.get(index).expect("how the fuck? we just made sure this works!!").clone()
    }

    pub fn check(&self, assumptions: &[&Bool<'z3_ctx>]) -> SatResult {
        self.state.optimizer.check(assumptions)
    }
    pub fn stats(&self) -> SymCCSamplerStatistics {
        self.state.stats
    }
    pub fn push_constraint(&mut self, constraint: Bool<'z3_ctx>) -> Result<(), MutationFailed> {
        self.state.push_new_constraint(constraint)
    }
    pub fn pop_constraint(&mut self, expected_constraint: Bool<'z3_ctx>) {
        self.state.pop_constraint(expected_constraint)
    }

    pub fn is_valid_model(&mut self, model: &SymCCModel<'z3_ctx>) -> bool {
        self.is_valid_bytes_model(model.concrete_bytes())
    }

    pub fn is_valid_bytes_model(&mut self, bytes: &[u8]) -> bool {
        self.state.is_bytes_valid_model(bytes)
    }

    pub fn to_smtlib2(&self) -> String {
        self.state.optimizer.to_string() + "\n(check-sat)\n"
    }

    pub fn quick_sample(&mut self, n_sample: usize) -> Vec<SymCCModel<'z3_ctx>> {
        // warn!("TODO: implement multiple epochs starting with fresh models instead of just one epoch");
        // unsafe { asm!("int3") };
        if self.state.optimizer.timed_check_assumptions(&[]) != SatResult::Sat {
            return vec![];
        }
        let original_model = SymCCModel::from_model(
            &self.state.optimizer.get_model().expect("We expect to always get a model??"),
            &self.state.variables
        );
        if n_sample == 1 {
            return vec![original_model];
        }

        // println!("Solver: {}", self.state.optimizer.to_string());
        // println!("original model: {:?}", original_model.concrete_bytes());

        let mut model_state = self.state.with_model_specialization(&original_model);

        // println!("Asserted soft equality for all inputs.");

        let start = Instant::now();
        let possible_primitive_mutations = model_state.state.get_constrained_mutation_locations();
        let (mut trivial_mut_locs, mut nontrivial_mut_locs): (Vec<_>, Vec<_>) = possible_primitive_mutations.into_iter().partition(|mut_loc| {
            model_state.is_primitive_mutation_trivial(*mut_loc)
        });

        log::info!("Discovered {} trivial and {} nontrivial potential mutations in {:?}", trivial_mut_locs.len(), nontrivial_mut_locs.len(), start.elapsed());

        log::info!("Shuffling mutations to ensure uniformity when subsampling ...");
        // let mut rng = ChaCha8Rng::seed_from_u64(2);
        let mut rng = thread_rng();

        trivial_mut_locs.shuffle(&mut rng);
        nontrivial_mut_locs.shuffle(&mut rng);

        let trivial_mut_locs = trivial_mut_locs.into_iter().take(n_sample).collect::<Vec<_>>(); // we don't need that many trivial mutations
        let _time_taken = start.elapsed();

        let trivial_muts = trivial_mut_locs.iter().map(
            |loc| model_state.get_primitive_mutation(*loc).expect("trivial mutations should never fail")
        ).collect::<Vec<_>>();

        let num_trivial = trivial_muts.len();

        let num_sampled_non_trivial_muts = (n_sample as f64).sqrt().ceil() as usize;
        let num_active = num_sampled_non_trivial_muts + num_trivial;
        log::info!(target: "quick_sample", "Selecting {} primitive mutations initially!", num_active);

        let mut initial_muts = Vec::with_capacity(num_active);
        for (i, &loc) in nontrivial_mut_locs.iter().enumerate() {
            if i >= num_sampled_non_trivial_muts {
                break;
            }
            if let Ok(mutation) = model_state.get_primitive_mutation(loc) {
                initial_muts.push(mutation);
            }
        }
        for trivial_mut in trivial_muts {
            initial_muts.push(trivial_mut);
        }

        std::mem::drop(model_state); // now that we have all mutations, dispose of the model-specific shit

        log::info!(target: "quick_sample", "Initial discovered mutations: {}, nontrivial={}", initial_muts.len(), initial_muts.len() - num_trivial);
        // initial_muts.iter().for_each(|x| {
        //     log::debug!(target: "quick_sample", "\t{:?}", x);
        // });

        // TODO Fuck with the non-constrained bytes as well (either separately or as part of dealing with the mutations
        // normally (e.g., at each step also try random bytes)

        let mut all_mutations: SortedSet<SymCCMutation> = initial_muts.clone()
            .into_iter()
            .collect::<Vec<_>>()
            .into();

        log::info!("Mutations used: {}", all_mutations.len());

        let mut all_solutions: HashSet<SymCCModel<'z3_ctx>> = initial_muts
            .iter()
            .map(|mutation| mutation.apply_to_model(&original_model))
            .chain([original_model.clone()].into_iter())
            .collect();

        warn!("TODO: implement backoff on too many invalid solutions, restart epoch. See SMTSampler paper");
        let mut mut_succ = vec![];
        for _epoch in 0..6 {
            // if all_solutions.len() >= n_sample * 2 {
            //     break;
            // }
            // println!("k: {}", k);
            let mut derivative_mutations = all_mutations
                .iter()
                .cartesian_product(initial_muts.iter())
                .collect::<Vec<_>>();
            derivative_mutations.shuffle(&mut thread_rng());

            let (mut mut_success, mut mut_new, mut mut_total) = (0, 0, 0);
            let mut new_valid_mutations = vec![];
            for (old, new) in derivative_mutations {
                if all_solutions.len() % 1000 == 0 {
                    log::info!("Sampled {} solutions in total!", all_solutions.len());
                    log::info!("new valid: {:?}, fully new: {}, at least valid: {}, total: {}", new_valid_mutations.len(), mut_new, mut_success, mut_total);
                }
                if all_solutions.len() >= n_sample {
                    break;
                }
                let new_mut = old.combine(new);

                let new_model = new_mut.apply_to_model(&original_model);
                if all_mutations.contains(&new_mut) {
                    continue;
                }

                if self.is_valid_model(&new_model) {
                    // println!("Discovered new VALID mutation! {:?}, resulting in {:?}", new_mut, &new_model);
                    // println!("Discovered new VALID mutation! {:?}", new_mut);
                    if !all_solutions.contains(&new_model) {
                        all_solutions.insert(new_model);
                        mut_new += 1;
                    }
                    mut_success += 1;
                    new_valid_mutations.push(new_mut);
                }
                mut_total += 1;
                // else {
                //     println!("Discovered new INVALID mutation! {:?}, resulting in {:?}", new_mut, &new_model);
                // }
            }
            log::info!("new valid: {:?}, fully new: {}, at least valid: {}, total: {}", new_valid_mutations.len(), mut_new, mut_success, mut_total);
            mut_succ.push((mut_new, mut_success, mut_total));
            if new_valid_mutations.len() > 0 {
                all_mutations.extend(new_valid_mutations.into_iter());
            }
            else {
                break;
            }
        }
        log::info!("Statistics: {:?}, got {} solutions in total", mut_succ, all_solutions.len());
        // for soln in &all_solutions {
        //     println!("Solution: {:?}", soln.concrete_bytes());
        // }

        // let mut final_solutions: Vec<SymCCModel> = Vec::with_capacity(all_solutions.len());
        // let mut already_expanded = RoaringBitmap::new();
        // for solution in all_solutions.into_iter() {

        //     let synthetic_indices = solution.byte_model.iter()
        //         .enumerate()
        //         .filter(|(i, x)| x.synthetic)
        //         .map(|(i, _)| i)
        //         .collect::<Vec<_>>();

        //     // println!("Attempting to expand solution {:?} synthetic_indices: {:?}...", solution, synthetic_indices);
        //     for (byte_idx, byte_model) in solution.byte_model.iter().enumerate() {
        //         if !byte_model.synthetic {
        //             continue;
        //         }
        //         if !solution.byte_model.get(byte_idx-1).map(|m| m.synthetic).unwrap_or(true) ||
        //             !solution.byte_model.get(byte_idx + 1).map(|m| m.synthetic).unwrap_or(true) {

        //             if !already_expanded.insert(byte_idx as u32) {
        //                 continue; // if the value was not absent previously => already expanded, skip
        //             }

        //             // the previous or next byte is non-synthetic, give us more variability in this one, aka all 256
        //             println!("Expanding synthetic byte {} to all 256 values", byte_idx);
        //             for i in 0..256u16 {
        //                 let mut model_copy = solution.clone();
        //                 model_copy.byte_model.get_mut(byte_idx).unwrap().value_u8 = i as u8;
        //                 final_solutions.push(model_copy);
        //             }
        //         }
        //     }
        //     final_solutions.push(solution)
        // }
        // println!("Expanded to final set of {} solutions", final_solutions.len());
        // final_solutions.into_iter()
        //     .sorted()
        //     .collect()
        let mut all_solutions = all_solutions.into_iter()
            .collect::<Vec<_>>();
        all_solutions.shuffle(&mut rng);

        let res: Vec<SymCCModel> = all_solutions
            .into_iter()
            .cycle()
            .take(n_sample)
            .sorted()
            .collect();
        // println!("Returning {} solutions", res.len());
        // for soln in &res {
        //     println!("Solution: {:?}", soln.concrete_bytes());
        // }
        res
    }
}
