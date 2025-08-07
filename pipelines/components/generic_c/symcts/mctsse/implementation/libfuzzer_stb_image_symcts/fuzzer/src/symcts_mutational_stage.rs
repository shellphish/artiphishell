//! This module contains the `concolic` stages, which can trace a target using symbolic execution
//! and use the results for fuzzer input and mutations.
//!

use core::marker::PhantomData;
use std::{fs::{File, OpenOptions}, io::Write, time::{SystemTime, UNIX_EPOCH, Duration}, collections::{HashSet, HashMap}, path::{Path, PathBuf}, cmp::{min, max}};

use concolic_trace_interpretation::{Z3TraceInterpreter, ConcolicTraceInterpreter, ConstraintKey};
use itertools::{Itertools, MinMaxResult};
use rand::seq::SliceRandom;
use rand_core::RngCore;

#[cfg(feature = "concolic_mutation")]
use alloc::{borrow::ToOwned, string::ToString, vec::Vec};
use libafl_bolts::{HasLen, rands::Rand, AsSlice};
use libafl::{
    corpus::{CorpusId, Testcase},
    state::{BetterStateTrait, HasRand, UsesState, HasSolutions, HasImported},
    ExecuteInputResult, monitors::UserStats, events::{EventFirer, Event}, observers::concolic::ConcolicMetadata, prelude::{UsesInput, HasObservers, Feedback, ObserversTuple, Executor, ExitKind}, ExecutesInput, ExecutionProcessor, StdFuzzer, schedulers::Scheduler,
};

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use smt_sampler::{self, symcc::SymCCSampler};

use libafl::{
    corpus::Corpus,
    inputs::Input,
    observers::concolic::Location,
    state::{HasClientPerfMonitor, HasCorpus, HasExecutions, HasMetadata},
    Error,
};

use libafl::stages::Stage;

use libafl::{
    inputs::HasBytesVec,
    mark_feature_time,
    start_timer, Evaluator,
};

#[cfg(all(feature = "introspection"))]
use libafl::monitors::PerfFeature;
use z3::{SatResult, Solver, ast::{Bool, Dynamic, Ast}, Config, Context, Model};
use z3jit::jit_constraint::JitContext;

use crate::{metadata::{global::SyMCTSGlobalMetadata, solve_stats::{SolveLocation, self, SymbolicSolveStats}}, disk_backed_concolic_metadata::{DiskBackedConcolicMetadata, ToDiskBackedConcolicMetadata}, coverage::{SyMCTSTestCaseAnnotationFeedback}, symcts_mutations::{MutationResultMetadata, MutationSource, MutationKind, Mutation}, concolic_synchronization::send_concolic_execution_event};

#[cfg(feature="coverage_mode_afl")]
use crate::coverage::afl_map::AFLBitmapCoverageMetadata;

macro_rules! timestamp {
    () => {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis()
    };
}

fn model_to_mutation<'z3_ctx>(model: Model<'z3_ctx>) -> Result<Vec<(usize, u8)>, String> {
    let mutation: Vec<(usize, u8)> = model.constants().into_iter().filter_map(|decl| {
        // println!("Decl: {:?}", decl);

        let name = decl.name();
        if !name.starts_with("k!") {
            return None;
        }
        let value = model.get_const_interpretation(&decl).map(|value| {
            // println!("Value: {:?}", value);
            value.as_bv().unwrap().as_u64().unwrap() as u8
        });
        let id = name[2..].parse::<usize>().unwrap();
        assert!(id % 10 == 0);
        let id = id / 10;
        value.map(|value| (id, value))
    }).collect();

    if mutation.len() == 0 {
        // constraint must have been trivially true, how did we not catch this?
        return Err(format!("No mutation found in model: {:?}", model));
    }
    // println!("Constraint {:?} => Model {:?} => Mutation {:?}", simplified_negated, model, mutation);
    return Ok(mutation);
}

#[allow(clippy::too_many_lines)]
fn generate_mutations_sampled<I, S>(
    sync_directory: &Path,
    debug_directory: &Path,
    _state: &mut S,
    corpus_id: CorpusId,
    borrowed_testcase: &mut Testcase<I>,
    source: Option<MutationSource>,
) -> Vec<Mutation>
where
    I: Input + HasBytesVec,
    S: HasMetadata + HasCorpus + HasRand + BetterStateTrait<Corpus=<S as HasCorpus>::Corpus>,
    <S as HasCorpus>::Corpus: Corpus<Input=I>,
{
    if !borrowed_testcase.has_metadata::<DiskBackedConcolicMetadata>() {
        // take the non-disk-backed concolic metadata, and convert it to disk-backed metadata
        let concolic_meta = if let Some(concolic_meta) = borrowed_testcase.metadata_map_mut().remove::<ConcolicMetadata>() {
            concolic_meta
        } else {
            panic!("no concolic metadata");
        };
        borrowed_testcase.add_metadata(
            concolic_meta.to_disk_backed_metadata(sync_directory, &format!("{}", corpus_id)),
        );
    };

    let input_filename = borrowed_testcase.filename().clone();

    let input_bytes = borrowed_testcase.load_input(
        _state.corpus()
    ).unwrap().bytes().to_vec();
    // dump debug info to `debug/<timestamp>` directory
    {
        File::create(debug_directory.join("input"))
            .unwrap()
            .write_all(&input_bytes)
            .unwrap();
        let mut file = File::create(debug_directory.join("symcc_trace_id")).unwrap();
        file.write_all(&format!("{:?}", &borrowed_testcase.metadata::<DiskBackedConcolicMetadata>().unwrap().path).as_bytes()).unwrap();
    }

    let mut res: Vec<Mutation> = vec![
        Mutation {
            source: MutationSource {
                kind: MutationKind::Original,
                source_filename: input_filename.clone(),
                corpus_id,
                constraint_key: (0, 0),
                location: SolveLocation::new(0.into(), 0.into(), 0),
                num_path_constraints_prior: 0,
                generational_would_have_skipped: false,
                own_solve_time: 0,
                current_backoff: 0,
                input_mutation_time_so_far: 0,
                input_mutation_time_total: 0,
            },
            changes: vec![],
        }
    ];

    let mut cfg = Config::new();
    cfg.set_timeout_msec(10_000);

    let ctx = Context::new(&cfg);

    #[cfg(any(feature="quicksampler_solving", feature="quicksampler_path_sensitive_solving"))]
    let jit_ctx = JitContext::create();
    #[cfg(any(feature="quicksampler_solving", feature="quicksampler_path_sensitive_solving"))]
    let mut sampler = SymCCSampler::new(&ctx, &jit_ctx);

    // this must be after `sampler`, `jit_ctx`, and `get_symbolic_byte_var` since the Drop implementations
    // of variables run in the opposite declaration order.
    // Therefore seen_path_constraints could reference the `z3_ctx` after it was dropped otherwise.
    let mut seen_path_constraints: Vec<(Bool, SolveLocation, Bool)> = vec![];

    #[cfg(feature="optimistic_solving")]
    let solver_optimistic = Solver::new(&ctx);
    #[cfg(feature="sage_solving")]
    let solver_sage = Solver::new(&ctx);
    #[cfg(feature="weak_solving")]
    let solver_weak = Optimize::new(&ctx);

    let mut last_location: Location = 0.into();

    let (rng, _, meta) = _state.get_state_components_rand_corpus_metadata();
    let solve_stats = meta.get_mut::<solve_stats::SymbolicSolveStats>().unwrap();
    let (min_num_inputs, max_num_inputs_produced) = match solve_stats.stats.values().map(|x| x.num_inputs_produced).filter(|&x| x > 0).minmax() {
        MinMaxResult::MinMax(min, max) => (min, max),
        MinMaxResult::OneElement(x) => (x, x),
        MinMaxResult::NoElements => (0, 0),
    };

    let pivot = if solve_stats.stats.len() > 0 {
        rng.choose(solve_stats.stats.values()).num_times_seen_feasible
    } else {
        0usize
    };

    let mut next_backoff = 1;
    let mut active_backoff = 0;

    let mut num_path_constraints = 0;

    let total_mutation_time_start = timestamp!();

    let mut total_solve_time_optimistic = 0;
    let mut total_solve_time_weak = 0;
    let mut total_solve_time_sage = 0;
    let mut total_solve_time_quicksampler = 0;

    let messages = borrowed_testcase
                        .metadata::<DiskBackedConcolicMetadata>()
                        .unwrap()
                        .iter_messages()
                        .collect_vec();

    if messages.len() == 0 {
        log::error!("No messages in concolic trace");
        return res; // no messages, no mutations, something went wrong
    }


    log::info!("Interpreting concolic trace of {} messages", messages.len());
    let mut interpreted_trace = Z3TraceInterpreter::new(&ctx)
        .enforce_concretization(false)
        .solve_for_concretization_alternatives(false);
    match interpreted_trace.interpret_messages_crash_resistant(messages) {
        Ok(()) => {},
        Err(e) => {
            log::error!("Error interpreting trace: {:?}", e);
            // dump the offending input and related information into <debug_directory>/.invalid_traces/<corpus_id>/
            let dump_dir = sync_directory.join(".invalid_traces").join(&format!("{}", corpus_id));
            std::fs::create_dir_all(&dump_dir).unwrap();
            let mut file = File::create(&dump_dir.join("input")).unwrap();
            file.write_all(&input_bytes).unwrap();
            let mut file = File::create(dump_dir.join("symcc_trace_id")).unwrap();
            file.write_all(&format!("{:?}", &borrowed_testcase.metadata::<DiskBackedConcolicMetadata>().unwrap().path).as_bytes()).unwrap();
            return res;
        }
    };

    // let mut next_var_index : usize = 0;
    let interpreted_constraints = interpreted_trace.unique_constraints_iter().collect_vec();
    log::info!("Interpreted trace into {} constraints", interpreted_constraints.len());
    let num_interpreted_constraints = interpreted_constraints.len();
    for (i, constraint_for_mutation) in interpreted_constraints.into_iter().enumerate()
    {
        let location = constraint_for_mutation.location;
        log::info!(
            target: "generate_mutations_sampled",
            "{}/{}: Mutating constraint at {:x?}",
            i, num_interpreted_constraints, constraint_for_mutation.source
        );

        let branch_sampling_time_start = timestamp!();
        num_path_constraints += 1;

        let cur_loc = SolveLocation::new(last_location, location, constraint_for_mutation.source.1);
        last_location = location;

        let constraint_guard = constraint_for_mutation.constraint_guard.clone();

        let cur_loc_updates = solve_stats.stats.entry(cur_loc.clone()).or_default();
        cur_loc_updates.num_times_seen += 1;
        cur_loc_updates.num_times_seen_since_last_successful_mutation += 1;

        match (constraint_for_mutation.is_divergent, constraint_for_mutation.constraint.as_bool()) {
            (_, None) => {},
            (true, Some(true)) => {
                // divergent constraint which is always true???? how is this possible?
                // just ignore it
                continue;
            }
            (true, Some(false)) => {
                // divergent constraint which cannot be satisfied, skip
                continue;
            }
            (false, Some(true)) => {
                // this path constraint is trivially sat => nothing to do here
                continue;
            }
            (false, Some(false)) => {
                // this constraint is somehow fucked, just ignore it (unsat in path constraint)
                continue;
            }
            _ => {
                // if false or symbolic continue to handle it normally
            }
        }
        cur_loc_updates.num_times_seen_symbolic += 1;

        let mut skip_mutation = false;
        let mut solve_result_optimistic:    Option<SatResult> = None;
        let mut solve_result_sage:          Option<SatResult> = None;
        let mut solve_result_weak:          Option<SatResult> = None;
        let mut solve_result_quicksampler:  Option<SatResult> = None;

        #[cfg(feature="solver_unknowns_exponential_backoff")]
        if active_backoff > 0 {
            active_backoff -= 1;
            skip_mutation = true;
        }

        #[cfg(feature = "solver_devalue_common_unknown_locations")]
        {
            if rng.below(
                (cur_loc_updates.num_times_seen_feasible + 1) as u64
                ) < cur_loc_updates.num_times_seen_unknown as u64 {
                // skip mutation with a #unknown / (#feasible + 1) chance to devalue resolving unseen
                skip_mutation = true;
            }
        }

        #[cfg(feature="solver_probabilistically_skip")]
        if constraint_for_mutation.is_divergent { // don't skip path constraints
            let range = max_num_inputs_produced + 1 - min_num_inputs;
            let rand = rng.between(min_num_inputs as u64, max_num_inputs_produced as u64 + 1);
            if rand < cur_loc_updates.num_inputs_produced as u64 {
                // 10 inputs produced, max = 100, if rng.below(100) <= 10, skip, 10% chance to skip, 90% chance to solve
                log::info!(target: "generate_mutations_sampled", "Skipping solve since rng.between({}, {})={} <= {}",
                    min_num_inputs,
                    max_num_inputs_produced + 1,
                    rand,
                    cur_loc_updates.num_inputs_produced
                );
                skip_mutation = true;
            }
        }
        // #[cfg(feature="solver_pivot_skip")]
        // {
        //     if cur_loc_updates.num_times_seen_feasible > pivot {
        //         // skip mutation if we've seen this location before
        //         log::info!(
        //             target: "generate_mutations_sampled",
        //             "Skipping solve, num_times_feasible={} < pivot={}",
        //             cur_loc_updates.num_times_seen_feasible,
        //             pivot
        //         );
        //         skip_mutation = true;
        //     }
        // }

        let mut generational_would_have_skipped = false;
        let generation_number = source.as_ref().map(|x| x.num_path_constraints_prior).unwrap_or(0);

        if num_path_constraints < generation_number {
            // log::debug!(target: "generate_mutations_sampled", "Skipping solve since {} < {}", num_path_constraints, source.num_path_constraints_prior);
            #[cfg(feature="sage_generational_search")]
            { skip_mutation = true; }
            generational_would_have_skipped = true;
        }

        #[cfg(feature = "debug_symcts")]
        let constraint_dir = debug_directory.join(format!("{}_{}", constraint_for_mutation.key.0, constraint_for_mutation.key.1));
        #[cfg(feature = "debug_symcts_constraints")]
        {
            // create directory for this id

            std::fs::create_dir_all(&constraint_dir).unwrap();
            println!("{}/{}: writing smt2 to {}/{}_{}.smt2", i, num_interpreted_constraints, debug_directory.display(), constraint_for_mutation.key.0, constraint_for_mutation.key.1);
            let solver = Solver::new(&ctx);
            for (constraint, loc, guard) in seen_path_constraints.iter() {
                solver.assert(constraint);
            }
            solver.assert(&constraint_for_mutation.constraint.not().simplify());
            let mut file = File::create(debug_directory.join(format!("{}_{}.smt2", constraint_for_mutation.key.0, constraint_for_mutation.key.1))).unwrap();
            file.write_all(solver.to_string().as_bytes()).unwrap();
            file.write_all("\n(check-sat)".as_bytes()).unwrap();
        }

        #[cfg(feature="optimistic_solving")]
        if !skip_mutation
        {
            if !constraint_for_mutation.is_divergent {
                // in optimistic solving we do not consider the actual path constraints, only the divergent ones
            }
            else {
                // but we do solve for the divergent ones individually
                let optimistic_solving_time_start = timestamp!();
                let solver = &solver_optimistic;
                solver.push();
                solver.assert(&constraint_for_mutation.constraint);
                log::debug!(target: "generate_mutations_sampled", "Optimistic solve...");
                solve_result_optimistic = Some(solver.check());
                let result = match solve_result_optimistic {
                    Some(SatResult::Unknown) => {
                        log::warn!(target: "generate_mutations_sampled", "Skipping other solves since since optimistic solve was unknown");
                        skip_mutation = true;
                        SatResult::Unknown
                    }
                    Some(x) => {
                        x
                    }
                    None => unreachable!("impossible")
                };
                let solve_time_optimistic = timestamp!() - optimistic_solving_time_start;
                if let SatResult::Sat = result {
                    cur_loc_updates.min_solve_time_optimistic = Some(min(cur_loc_updates.min_solve_time_optimistic.unwrap_or(solve_time_optimistic), solve_time_optimistic));
                    cur_loc_updates.max_solve_time_optimistic = Some(max(cur_loc_updates.max_solve_time_optimistic.unwrap_or(solve_time_optimistic), solve_time_optimistic));

                    let model = solver.get_model().or_else(|| {
                        panic!("solver returned sat but no model was available: {:?}", solver.to_string());
                    }).unwrap();
                    let mutation = match model_to_mutation(model) {
                        Ok(mutation) => mutation,
                        Err(e) => {
                            panic!("solver returned sat but no mutation was available: \n\tSolver: {:?}\n\t{:?}\n\tConstraint: {:?}", solver, e, &constraint_for_mutation.constraint);
                        }
                    };

                    // println!("Constraint {:?} => Model {:?} => Mutation {:?}", simplified_negated, model, mutation);
                    res.push(Mutation {
                        source: MutationSource {
                            kind: MutationKind::OptimisticSolving,
                            source_filename: input_filename.clone(),
                            corpus_id,
                            constraint_key: constraint_for_mutation.key,
                            location: cur_loc.clone(),
                            // optimistic solving does not guarantee the path predicate is maintained, so we have to
                            // restart the generation
                            num_path_constraints_prior: 0,
                            generational_would_have_skipped,
                            own_solve_time: timestamp!().abs_diff(optimistic_solving_time_start),
                            current_backoff: next_backoff,
                            input_mutation_time_so_far: total_mutation_time_start.abs_diff(timestamp!()),
                            input_mutation_time_total: 0,
                        },
                        changes: mutation
                    });
                    cur_loc_updates.num_inputs_produced += 1;
                    cur_loc_updates.num_inputs_produced_since_last_successful_mutation += 1;
                    total_solve_time_optimistic += timestamp!().abs_diff(optimistic_solving_time_start);
                }
                solver.pop(1);
                cur_loc_updates.total_time_solved_for_optimistic += solve_time_optimistic;
            }
        }

        #[cfg(feature="sage_solving")]
        if !skip_mutation
        {
            if !constraint_for_mutation.is_divergent {
                // for path constraints, add them to the solver
                solver_sage.assert_and_track(
                    &constraint_for_mutation.constraint,
                    &constraint_for_mutation.constraint_guard
                );
            }
            else {
                // for divergent constraints, attempt to find a mutation that satisfies the constraint
                let sage_solving_time_start = timestamp!();
                let solver = &solver_sage;
                solver.push();
                solver.assert(&constraint_for_mutation.constraint);
                log::debug!(target: "generate_mutations_sampled", "SAGE solve...");
                solve_result_sage = Some(solver.check());
                let solver_result = match solve_result_sage {
                    Some(SatResult::Unknown) => {
                        log::warn!(target: "generate_mutations_sampled", "Sage solve was unknown");
                        SatResult::Unknown
                    }
                    Some(x) => {
                        x
                    }
                    None => unreachable!("impossible")
                };
                let solve_time_sage = timestamp!() - sage_solving_time_start;
                if let SatResult::Sat = solver_result {
                    cur_loc_updates.min_solve_time_sage = Some(min(cur_loc_updates.min_solve_time_sage.unwrap_or(solve_time_sage), solve_time_sage));
                    cur_loc_updates.max_solve_time_sage = Some(max(cur_loc_updates.max_solve_time_sage.unwrap_or(solve_time_sage), solve_time_sage));
                    let model = solver.get_model().or_else(|| {
                        panic!("solver returned sat but no model was available: {:?}", solver.to_string());
                    }).unwrap();
                    let mutation = match model_to_mutation(model) {
                        Ok(mutation) => mutation,
                        Err(e) => {
                            panic!("solver returned sat but no mutation was available: \n\tSolver: {:?}\n\t{:?}\n\tConstraint: {:?}", solver, e, &constraint_for_mutation.constraint);
                        }
                    };

                    res.push(Mutation {
                        source: MutationSource {
                            kind: MutationKind::SageSolving,
                            source_filename: input_filename.clone(),
                            corpus_id,
                            constraint_key: constraint_for_mutation.key,
                            location: cur_loc.clone(),
                            num_path_constraints_prior: num_path_constraints,
                            generational_would_have_skipped,
                            own_solve_time: timestamp!().abs_diff(sage_solving_time_start),
                            current_backoff: next_backoff,
                            input_mutation_time_so_far: total_mutation_time_start.abs_diff(timestamp!()),
                            input_mutation_time_total: 0,
                        },
                        changes: mutation
                    });

                    cur_loc_updates.num_inputs_produced += 1;
                    cur_loc_updates.num_inputs_produced_since_last_successful_mutation += 1;
                    total_solve_time_sage += timestamp!().abs_diff(sage_solving_time_start);
                }
                else {
                    #[cfg(feature="unsat_cores")]
                    if let SatResult::Unsat = solver_result {
                        let unsat_core = solver.get_unsat_core();
                        println!("Unsat core: {:?}", unsat_core);
                    }
                }
                solver_sage.pop(1); // pop the divergent constraint context
                cur_loc_updates.total_time_solved_for_sage += solve_time_sage;
            }
        }

        // weak solving if full path feasibility didn't work
        #[cfg(feature="weak_solving")]
        if !skip_mutation && solve_result_sage != Some(SatResult::Sat) {
            let weak_solving_time_start = timestamp!();
            let solver = &solver_weak;
            solver.push();
            solver.assert(&simplified_negated);
            log::debug!(target: "generate_mutations_sampled", "Weak solve...");
            solve_result_weak = Some(solver.check(&[]));
            let result = solve_result_weak.unwrap();
            let solve_time_weak = timestamp!() - weak_solving_time_start;
            if let SatResult::Sat = result {
                cur_loc_updates.min_solve_time_weak = Some(min(cur_loc_updates.min_solve_time_weak.unwrap_or(solve_time_weak), solve_time_weak));
                cur_loc_updates.max_solve_time_weak = Some(max(cur_loc_updates.max_solve_time_weak.unwrap_or(solve_time_weak), solve_time_weak));
                let model = solver.get_model().or_else(|| {
                    panic!("solver returned sat but no model was available: {:?}", solver.to_string());
                }).unwrap();
                let mutation = match model_to_mutation(model) {
                    Ok(mutation) => mutation,
                    Err(e) => {
                        panic!("solver returned sat but no mutation was available: \n\tSolver: {:?}\n\t{:?}\n\tConstraint: {:?}", solver, e, &op);
                    }
                };

                res.push(Mutation {
                    source: MutationSource {
                        kind: MutationKind::WeakSolving,
                        source_filename: input_filename.clone(),
                        corpus_id,
                        constraint_key,
                        location: cur_loc.clone(),
                        // weak solving does not guarantee the path predicate is maintained, so we have to
                        // restart the generation
                        num_path_constraints_prior: 0,
                        generational_would_have_skipped,
                        own_solve_time: timestamp!().abs_diff(weak_solving_time_start),
                        current_backoff: next_backoff,
                        input_mutation_time_so_far: total_mutation_time_start.abs_diff(timestamp!()),
                        input_mutation_time_total: 0,
                    },
                    changes: mutation
                });
                cur_loc_updates.num_inputs_produced += 1;
                cur_loc_updates.num_inputs_produced_since_last_successful_mutation += 1;
                total_solve_time_weak += timestamp!().abs_diff(weak_solving_time_start);
            }
            else {
                #[cfg(feature="unsat_cores")]
                if let SatResult::Unsat = solver_result {
                    let unsat_core = solver.get_unsat_core();
                    println!("Unsat core: {:?}", unsat_core);
                }
            }
            solver.pop();
            solver.assert_soft(&op, 1, None); // soft assert the original path constraint
            cur_loc_updates.total_time_solved_for_weak += solve_time_weak;
        }

        // let mut neg_constraints = csts.iter().cloned().collect::<Vec<_>>();

        #[cfg(any(feature="quicksampler_solving", feature="quicksampler_path_sensitive_solving"))]
        if !skip_mutation {
            let quicksampler_time_start = timestamp!();
            log::debug!(target: "generate_mutations_sampled", "Quicksampler solve...");
            let sampler_check_result = sampler.check(&[&simplified_negated]);
            solve_result_quicksampler = Some(sampler_check_result);
            match sampler_check_result {
                SatResult::Sat => {
                    let solve_time_quicksampler = timestamp!().abs_diff(quicksampler_time_start);
                    cur_loc_updates.min_solve_time_quicksampler = Some(min(cur_loc_updates.min_solve_time_quicksampler.unwrap_or(solve_time_quicksampler), solve_time_quicksampler));
                    cur_loc_updates.max_solve_time_quicksampler = Some(max(cur_loc_updates.max_solve_time_quicksampler.unwrap_or(solve_time_quicksampler), solve_time_quicksampler));

                    cur_loc_updates.num_times_seen_feasible += 1;
                    cur_loc_updates.num_times_seen_feasible_since_last_successful_mutation += 1;
                    let num_samples: usize = 16;
                    #[cfg(feature="adaptive_sampling_scaling")]
                    let num_samples = {
                        let num_samples = 4; // for this mode we start at 4
                        let scaling_factor = 1 + scheduling_info.1.num_times_symbolically_sampled;
                        println!("scaling factor: {}", scaling_factor);
                        let scaled_num_samples = min(num_samples * scaling_factor, 0x10000);
                        scaled_num_samples
                    };
                    if !skip_mutation && sampler.push_constraint(simplified_negated.clone()).is_ok() {
                        let sampled_results = sampler.quick_sample(num_samples);
                        for result in sampled_results.iter() {
                            if !sampler.is_valid_model(result) {
                                let invalid_model_dir = sync_directory.join(".invalid_model");
                                std::fs::create_dir_all(&invalid_model_dir).unwrap();
                                // write out the sampler smtlib to /tmp/invalid_model_sampled.smt2
                                let mut file = File::create(invalid_model_dir.join("constraints.smt2")).unwrap();
                                file.write_all(sampler.to_smtlib2().as_bytes()).unwrap();
                                // write out the model too
                                let mut file = File::create(invalid_model_dir.join("model")).unwrap();
                                file.write_all(&result.concrete_bytes().clone()).unwrap();
                                // and a debbug print of the model
                                let mut file = File::create(invalid_model_dir.join("model.debug")).unwrap();
                                file.write_all(format!("{:?}", result).as_bytes()).unwrap();
                                println!("This should never happen, quicksampler returned an invalid model??");
                            }
                        }
                        sampler.pop_constraint(simplified_negated.clone());

                        cur_loc_updates.num_inputs_produced += sampled_results.len() * 2;
                        cur_loc_updates.num_inputs_produced_since_last_successful_mutation += sampled_results.len() * 2;
                        total_solve_time_quicksampler += timestamp!().abs_diff(quicksampler_time_start);

                        res.append(
                            &mut sampled_results
                                .iter()
                                .enumerate()
                                .map(|(_i, sampled_model)| {
                                    let mutations_randomized = sampled_model
                                        .randomize_unconstrained_bytes(input_bytes.len())
                                        .into_iter()
                                        .enumerate()
                                        .collect::<Vec<(usize, u8)>>();

                                    let mutations_minimal = sampled_model
                                        .concrete_bytes()
                                        .iter()
                                        .cloned()
                                        .enumerate()
                                        .collect::<Vec<_>>();
                                    vec![
                                        #[cfg(feature="quicksampler_solving")]
                                        Mutation {
                                            source: MutationSource {
                                                kind: MutationKind::SymCCSampling,
                                                source_filename: input_filename.clone(),
                                                constraint_key,
                                                corpus_id,
                                                location: cur_loc.clone(),
                                                num_path_constraints_prior: num_path_constraints,
                                                generational_would_have_skipped,
                                                own_solve_time: timestamp!().abs_diff(quicksampler_time_start),
                                                current_backoff: next_backoff,
                                                input_mutation_time_so_far: total_mutation_time_start.abs_diff(timestamp!()),
                                                input_mutation_time_total: 0,
                                            },
                                            changes: mutations_randomized,
                                        },
                                        #[cfg(feature="quicksampler_path_sensitive_solving")]
                                        Mutation {
                                            source: MutationSource {
                                                kind: MutationKind::SymCCSamplingPathPreserving,
                                                source_filename:  input_filename.clone(),
                                                corpus_id,
                                                constraint_key,
                                                location: cur_loc.clone(),
                                                num_path_constraints_prior: num_path_constraints,
                                                generational_would_have_skipped,
                                                own_solve_time: timestamp!().abs_diff(quicksampler_time_start),
                                                current_backoff: next_backoff,
                                                input_mutation_time_so_far: total_mutation_time_start.abs_diff(timestamp!()),
                                                input_mutation_time_total: 0,
                                            },
                                            changes: mutations_minimal,
                                        }
                                    ]
                                })
                                .flatten()
                                .collect::<Vec<_>>(),
                        )
                    }
                }
                SatResult::Unknown => {
                    // We have a problem

                    // if one constraint times out, the next ones probably will too, let's do some exponential backoff
                    // to avoid timing out all the time
                }
                SatResult::Unsat => {
                    //negation is unsat => continue, ignore this constraint
                    continue;
                }
            }
            cur_loc_updates.total_time_solved_for_quicksampler += timestamp!().abs_diff(quicksampler_time_start);
        }

        let any_unknowns = [solve_result_optimistic, solve_result_weak, solve_result_sage, solve_result_quicksampler]
            .iter()
            .any(|x| match x { Some(SatResult::Unknown) => true, _ => false });
        if any_unknowns {
            // if any of the solvers timed out, we need to do some exponential backoff
            // to avoid timing out all the time
            assert!(active_backoff == 0);
            active_backoff = next_backoff;
            next_backoff *= 2;
            cur_loc_updates.num_times_seen_unknown += 1;

            if let Some(SatResult::Unknown) = solve_result_optimistic { cur_loc_updates.num_times_seen_unknown_optimistic += 1; }
            if let Some(SatResult::Unknown) = solve_result_weak { cur_loc_updates.num_times_seen_unknown_weak += 1; }
            if let Some(SatResult::Unknown) = solve_result_sage { cur_loc_updates.num_times_seen_unknown_sage += 1; }
            if let Some(SatResult::Unknown) = solve_result_quicksampler { cur_loc_updates.num_times_seen_unknown_quicksampler += 1; }

            std::fs::OpenOptions::new()
                .append(true)
                .create(true)
                .open(debug_directory.join("solver_unknowns_sampling"))
                .unwrap()
                .write_all(format!("{:x?}\t{:?}\t{:?}\n", constraint_for_mutation.key, cur_loc, cur_loc_updates).as_bytes())
                .unwrap();

            //     .unwrap();
            // let unknowns_dir = debug_directory.join("solver_unknowns_sampling");
            // std::fs::create_dir_all(&unknowns_dir).unwrap();
            // let mut file = File::create(unknowns_dir.join(format!("{}.smt2", id))).unwrap();

            // file.write_all(sampler.to_smtlib2().as_bytes()).unwrap();
            // file.write_all(format!("\n\n; optimistic was unknown: {}", solve_result_optimistic).as_bytes()).unwrap();
            // file.write_all(format!("\n\n; sage was unknown: {}", solve_result_sage).as_bytes()).unwrap();
            // file.write_all(format!("\n\n; quicksampler was unknown: {}", solve_result_quicksampler).as_bytes()).unwrap();
            // file.write_all(format!("\n\n; attempted constraint (negated of original)\n{}", simplified_negated).as_bytes()).unwrap();

            log::warn!("Solver unknown in sampling");
        }

        // assert the path constraint
        #[cfg(any(feature="quicksampler_solving", feature="quicksampler_path_sensitive_solving"))]
        if !skip_mutation && !solve_result_quicksampler.map(|x| x == SatResult::Unknown).unwrap_or(true) {
            // if optimistic was unknown, there's no reason to even attempt to append this to the path constraint
            let solver_result = sampler.push_constraint(op.clone()).map_err(|err| match err{
                MutationFailed::SolverUnknown { reason, constraints_smt2 } => {
                    (format!("Solver unknown in taken path constraint, reason: {:?}", reason), constraints_smt2)
                },
                MutationFailed::SolverUnsat { core, constraints_smt2 } => {
                    let unsat_path_constraints_dir = debug_directory.join("unsat_path_constraints");
                    std::fs::create_dir_all(&unsat_path_constraints_dir).unwrap();

                    // log to unsat_{time}_{pos}.symcc_trace
                    let mut file = File::create(
                        unsat_path_constraints_dir.join(
                            format!("unsat_{}_{:x?}.trace_id",
                                timestamp!(),
                                constraint_key,
                            )
                        )
                    ).unwrap();
                    file.write_all(
                        &format!("{:?}",
                            &borrowed_testcase.metadata::<DiskBackedConcolicMetadata>()
                                .unwrap()
                                .path).as_bytes()
                        ).unwrap();

                    (format!("Solver unsat in taken path constraint, core: {:?}", core), constraints_smt2)
                },
            });

            if let Err((msg, csts_smt2)) = solver_result {
                log::info!(target: "generate_mutations_sampled", "Error: {}, solver: {:?}", msg, csts_smt2);
                break;
            }
        }

        cur_loc_updates.total_time_solved_for += branch_sampling_time_start.abs_diff(timestamp!());

        if !constraint_for_mutation.is_divergent {
            seen_path_constraints.push((constraint_for_mutation.constraint.clone(), cur_loc, constraint_guard));
        }
    }

    log::info!(target: "generate_mutations_sampled", "Number of mutations produced: {:?}", res.len());

    let total_mutation_time = timestamp!();
    for m in &mut res {
        m.source.input_mutation_time_total = total_mutation_time.abs_diff(total_mutation_time_start);
    }
    {
        let mutation_solve_times_log_path = debug_directory.join("mutation_solve_times");
        let mut file = File::create(mutation_solve_times_log_path).unwrap();
        file.write_all(format!("optimistic={} weak={} sage={} quicksampler={} total={}",
            total_solve_time_optimistic,
            total_solve_time_weak,
            total_solve_time_sage,
            total_solve_time_quicksampler,
            total_mutation_time.abs_diff(total_mutation_time_start)
        ).as_bytes()).unwrap();
    }

    #[cfg(feature="debug_symcts_testcases")]
    for m in &res
    {
        let constraint_dir = debug_directory.join(format!("{}_{}", m.source.constraint_key.0, m.source.constraint_key.1));
        std::fs::create_dir_all(&constraint_dir).unwrap();
        // check that all mutations are in order
        let mut i = 0;
        let path = loop {
            let path = constraint_dir.join(format!("{:?}_{}", m.source.kind, i));
            if !path.exists() {
                break path;
            }
            i += 1;
        };
        let mut file = File::create(path).unwrap();
        let mut bytes = input_bytes.clone();
        for (idx, new) in m.changes.iter() {
            bytes[*idx] = *new;
        }
        file.write_all(&bytes).unwrap();
    }

    res
}

/// A mutational stage that uses Z3 to solve concolic constraints attached to the [`crate::corpus::Testcase`] by the [`ConcolicTracingStage`].
#[derive(Clone, Debug)]
pub struct SyMCTSMutationalStage<E, EM, Z>
{
    _phantom: PhantomData<(E, EM, Z)>,
}

impl<E, EM, Z> UsesState for SyMCTSMutationalStage<E, EM, Z>
where
    Z: UsesState,
{
    type State = Z::State;
}

impl<E, EM, CS, F, OF, OT> Stage<E, EM, StdFuzzer<CS, F, OF, OT>> for SyMCTSMutationalStage<E, EM, StdFuzzer<CS, F, OF, OT>>
where
    CS: Scheduler,
    F: Feedback<CS::State>,
    OF: Feedback<CS::State>,
    OT: ObserversTuple<CS::State> + Serialize + DeserializeOwned,
    CS::State: HasClientPerfMonitor,
    <CS as UsesState>::State: HasExecutions + HasSolutions,
    E: UsesState<State = CS::State> + HasObservers<Observers = OT> + Executor<EM, StdFuzzer<CS, F, OF, OT>>,
    EM: UsesState<State = CS::State> + EventFirer<State = CS::State>,
    CS::State: UsesInput + HasClientPerfMonitor + HasMetadata + HasCorpus + HasRand + BetterStateTrait<Corpus=<CS::State as HasCorpus>::Corpus> + HasImported,
    <<CS as UsesState>::State as UsesInput>::Input: HasLen + HasBytesVec ,
    <<CS as UsesState>::State as HasRand>::Rand: RngCore,
{
    #[inline]
    fn perform(
        &mut self,
        fuzzer: &mut StdFuzzer<CS, F, OF, OT>,
        executor: &mut E,
        state: &mut CS::State,
        manager: &mut EM,
        corpus_idx: CorpusId,
    ) -> Result<(), Error> {

        send_concolic_execution_event::<CS::State, E, EM>(manager, state, corpus_idx).expect("failed to send concolic execution event");
        start_timer!(state);
        {
            let (
                num_times_sampled,
                inputs_sampled_by_us,
                inputs_sampled_by_others,
                inputs_sampled_by_both,
                inputs_unsampled
            ) = {
                let meta = state.metadata_mut::<SyMCTSGlobalMetadata>().expect("no global metadata?");

                let mut num_us: usize = 0;
                let mut num_others: usize = 0;
                let mut num_both: usize = 0;
                let mut num_unsampled: usize = 0;
                for (hash, (sampled_us, sampled_others)) in meta.traced_inputs.iter() {
                    match (sampled_us, sampled_others) {
                        (0, 0) => panic!("this should not happen??"),
                        (0, _) => num_others += 1,
                        (_, 0) => num_us += 1,
                        (_, _) => num_both += 1,
                    }
                }
                for hash in meta.hash_to_corpus_id.keys() {
                    if !meta.traced_inputs.contains_key(hash) {
                        num_unsampled += 1;
                    }
                }

                (
                    meta.total_num_times_sampled,
                    num_us,
                    num_others,
                    num_both,
                    num_unsampled,
                )
            };
            manager.fire(
                state,
                Event::UpdateUserStats {
                    name: "symmut".to_owned(),
                    // value: UserStats::Ratio(num_cov_points as u64, state.metadata::<SyMCTSGlobalMetadata>().unwrap().coverage_point_info.len() as u64),
                    value: UserStats::Number(num_times_sampled as u64),
                    phantom: PhantomData,
                },
            )?;
            manager.fire(
                state,
                Event::UpdateUserStats {
                    name: "symmut_self".to_owned(),
                    // value: UserStats::Ratio(num_cov_points as u64, state.metadata::<SyMCTSGlobalMetadata>().unwrap().coverage_point_info.len() as u64),
                    value: UserStats::Number(inputs_sampled_by_us as u64),
                    phantom: PhantomData,
                },
            )?;
            manager.fire(
                state,
                Event::UpdateUserStats {
                    name: "symmut_dup".to_owned(),
                    // value: UserStats::Ratio(num_cov_points as u64, state.metadata::<SyMCTSGlobalMetadata>().unwrap().coverage_point_info.len() as u64),
                    value: UserStats::Number(inputs_sampled_by_both as u64),
                    phantom: PhantomData,
                },
            )?;
            manager.fire(
                state,
                Event::UpdateUserStats {
                    name: "symmut_rem".to_owned(),
                    // value: UserStats::Ratio(num_cov_points as u64, state.metadata::<SyMCTSGlobalMetadata>().unwrap().coverage_point_info.len() as u64),
                    value: UserStats::Number(inputs_unsampled as u64),
                    phantom: PhantomData,
                },
            )?;
        }

        let sync_dir: PathBuf = state.metadata::<SyMCTSGlobalMetadata>().unwrap().sync_dir.clone();

        let testcase = state.corpus().get(corpus_idx)?.clone();
        mark_feature_time!(state, PerfFeature::GetInputFromCorpus);

        // get current timestamp in second
        let start_time = timestamp!();

        // in debug, create dump directory with current timestamp and corpus_idx
        let debug_directory_path = sync_dir.join(format!(
            ".debug_symcts/{timestamp}_{corpus_idx}/",
            corpus_idx = corpus_idx,
            timestamp = start_time,
        ));
        std::fs::create_dir_all(&debug_directory_path).unwrap();
        let mutation_source = testcase.borrow().metadata::<MutationSource>().ok().cloned();
        let time_start_mutate = timestamp!();

        start_timer!(state);
        let mutations = generate_mutations_sampled(
            &sync_dir, &debug_directory_path,
            state, corpus_idx,
            &mut testcase.borrow_mut(), mutation_source
        );
        mark_feature_time!(state, PerfFeature::Mutate);

        let time_taken_mutation = time_start_mutate.abs_diff(timestamp!());

        let mut seen_inputs = HashSet::<Vec<u8>>::new();
        let mut logfile = OpenOptions::new()
            .append(true)
            .create(true)
            .open(debug_directory_path.join(".successful_symcts_mutations.tsv"))
            .unwrap();
        // shuffle the mutations to get a fair distribution
        // let mut rng = state.rand_mut();
        // if let Some(mutations) = &mut mutations {
        //     mutations.shuffle(&mut rng);
        // }
        let cov_start = state.metadata::<SyMCTSGlobalMetadata>().unwrap().coverage_point_info.len();
        let mut mutations = mutations; // remove mutability
        mutations.sort_by_key(|x| x.source.kind);
        // mutations.shuffle(state.rand_mut());
        logfile
            .write_all(&format!("######## {:?} => {:?}: {}\n",
                                     corpus_idx,
                                     testcase.borrow().filename(),
                                     cov_start
                        ).as_bytes()
                    ).unwrap();

        let mut times_seen_timed_out = HashMap::<(MutationKind, ConstraintKey), u8>::new();
        let time_start_tracing = timestamp!();
        {
            let input = { testcase.borrow().input().as_ref().unwrap().clone() };

            let mut successfull_mut_locs = vec![];
            #[cfg(feature="debug_stats_csv")]
            let mut stats_csv = {
                let f = OpenOptions::new()
                    .append(true)
                    .create(true)
                    .open(sync_dir.join(".symcts_stats.csv"))
                    .unwrap();
                f.write_all("times_seen, times_seen_symbolic, num_inputs_produced, num_successful_mutations\n".as_bytes()).unwrap();
                f
            };
            for mutation in &mutations {
                let mut input_copy = input.to_owned();
                for (index, new_byte) in &mutation.changes {
                    input_copy.bytes_mut()[*index] = *new_byte;
                }
                if !seen_inputs.insert(input_copy.bytes().to_vec()) {
                    // println!("input {:?} was produced by multiple mutations??", input_copy.bytes());
                    continue;
                }

                let times_seen_hang = times_seen_timed_out.entry((mutation.source.kind, mutation.source.constraint_key)).or_insert(0);
                if *times_seen_hang >= 3 {
                    // after 2 separate timeouts from the constraint, we assume there's something fundamentally wrong with it
                    // and stop tracing the rest to avoid wasting time
                    log::warn!("Constraint {:?}({:?}) timed out 3 times, refusing to trace more inputs for this constraint", mutation.source.constraint_key, mutation.source.kind );
                    continue;
                }

                let cov_before = state.metadata::<SyMCTSGlobalMetadata>().unwrap().coverage_point_info.len();
                // Time is measured directly the `evaluate_input` function
                let exit_kind = fuzzer.execute_input(state, executor, manager, &input_copy)?;
                let observers = executor.observers();
                let (result, res_corpus_id) =
                    fuzzer.process_execution(state, manager, input_copy, observers, &exit_kind, true)?;

                if exit_kind == ExitKind::Timeout {
                    let times_seen = times_seen_timed_out.entry((mutation.source.kind, mutation.source.constraint_key)).or_insert(0);
                    *times_seen += 1;
                }

                let mut_loc = mutation.source.location.clone();
                let cov_after = state.metadata::<SyMCTSGlobalMetadata>().unwrap().coverage_point_info.len();

                if result == ExecuteInputResult::Corpus || result == ExecuteInputResult::Solution {
                    // log the successful mutation

                    let stats_entry = state.metadata::<SymbolicSolveStats>().unwrap().stats.get(&mut_loc).cloned().unwrap_or_default();

                    let timestamp = timestamp!();
                    logfile
                        .write_all(format!(
                            "      {}\t{:?}\t{:?}\t{:?}\t{}\t{}\n",
                            timestamp,
                            result,
                            mutation.source,
                            stats_entry,
                            cov_before,
                            cov_after).as_bytes()).unwrap();

                    if result == ExecuteInputResult::Corpus {
                        let corpus_id = res_corpus_id.unwrap();
                        let mut tc = state.corpus().get(corpus_id).unwrap().borrow_mut();
                        tc.add_metadata(mutation.source.clone());
                        tc.set_parent_id(corpus_idx);
                        successfull_mut_locs.push(mut_loc.clone());
                    }
                } else {
                    assert!(res_corpus_id.is_none());
                }

                #[cfg(feature="debug_stats_csv")]
                {
                    let stats_entry = state
                        .metadata::<SymbolicSolveStats>()
                        .expect("Could not find symbolic solve stats???")
                        .stats
                        .get(&mut_loc)
                        .cloned()
                        .unwrap_or_default();
                    stats_csv.write_all(
                        format!("{}, {}, {}, {}, {}, {}, {:?}, {}, {}\n",
                            stats_entry.num_times_seen,
                            stats_entry.num_times_seen_symbolic,
                            stats_entry.num_times_seen_feasible,
                            stats_entry.num_inputs_produced,
                            stats_entry.num_successful_mutations,
                            stats_entry.num_inputs_produced_since_last_successful_mutation,
                            result,
                            cov_before,
                            cov_after).as_bytes()
                        ).unwrap();
                }
            }

            let stats_meta = state.metadata_mut::<SymbolicSolveStats>().unwrap();
            for loc in successfull_mut_locs {
                let cur = stats_meta.stats.entry(loc).or_default();
                cur.num_successful_mutations += 1;
                cur.num_inputs_produced_since_last_successful_mutation = 0;
                cur.num_times_seen_since_last_successful_mutation = 0;
                cur.num_times_seen_feasible_since_last_successful_mutation = 0;
            }
            // log stats_meta to file as json
            // let mut stats_file = OpenOptions::new()
            //     .append(true)
            //     .create(true)
            //     .open(sync_dir.join(".symcts_stats.json"))
            //     .unwrap();

            // stats_file.write_all(serde_json::to_string(&stats_meta).unwrap().as_bytes()).unwrap();
        }
        let cov_after_tracing = state.metadata::<SyMCTSGlobalMetadata>().unwrap().coverage_point_info.len();
        if cov_after_tracing != cov_start {
            log::info!("Coverage increased! {} -> {}", cov_start, cov_after_tracing);
            state.metadata_mut::<SyMCTSGlobalMetadata>().unwrap().reset_stuck_counter();
        }
        let time_taken_tracing = timestamp!().abs_diff(time_start_tracing);
        OpenOptions::new()
            .append(true)
            .create(true)
            .open(debug_directory_path.join(".time_stats.tsv"))
            .unwrap()
            .write_all(format!("{}\t{}\t{}\t{}\n", time_taken_mutation, time_taken_tracing, mutations.len(), seen_inputs.len()).as_bytes())
            .unwrap();

        // write global_meta to ".debug_symcts/global_meta_{timestamp}.json"
        #[cfg(feature = "debug_symcts_metadata")]
        {
            let global_meta = state.metadata::<SyMCTSGlobalMetadata>().unwrap();
            let path = debug_directory_path.join("global_meta_after.json");

            println!("writing global_meta to {}", path.display());
            let file = File::create(path).unwrap();
            serde_json::to_writer(file, global_meta).unwrap();
        }
        // println!("{:?}: {:#?}", corpus_idx, testcase.borrow().metadata());

        let end_time = timestamp!();
        if end_time - start_time < 5 {
            // every mutation should at least take 5 seconds, if not something is wrong, so let's pause to avoid
            // spewing debug info to disk
            std::thread::sleep(Duration::from_secs(5));
        }

        Ok(())
    }
}

impl<E, EM, Z> SyMCTSMutationalStage<E, EM, Z>
{
    pub fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
}
