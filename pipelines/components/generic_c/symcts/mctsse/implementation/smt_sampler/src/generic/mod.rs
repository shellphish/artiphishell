
mod model_mutation;
mod simple_model;

use std::collections::HashMap;
use itertools::Itertools;

use log::warn;
use rand::{thread_rng, seq::SliceRandom};
use sorted_vec::SortedSet;
use z3::{SortKind, FuncDecl, SatResult, Context, Optimize};
use z3::ast::{Ast, BV, Bool};
use simple_model::SimpleModel;
use super::{BitConstraintGuards, BoolConstraintGuards, Guard, GUARD_PREFIX};
use crate::z3_util::z3_timed::TimedSolver;

use self::model_mutation::ModelMutation;

#[derive(Debug)]
pub enum PrimitiveMutationLocation<'ctx> {
    Bit { decl: FuncDecl<'ctx>, bit_idx: u32 },
    Bool { decl: FuncDecl<'ctx> }
}
pub enum MutationFailed<'ctx> {
    SolverUnsat { core: Vec<Bool<'ctx>> },
    SolverUnknown { reason: Option<String> }
}

pub struct SmtSampler<'ctx> {
    ctx: &'ctx Context,
    constraints: Vec<Bool<'ctx>>,
    optimizer: Optimize<'ctx>,
    original_constraint_guard_variables: HashMap<Bool<'ctx>, Guard<'ctx>>,
    soft_bit_constraint_guard_variables: HashMap<(BV<'ctx>, u32), BitConstraintGuards<'ctx>>,
    soft_bool_constraint_guard_variables: HashMap<Bool<'ctx>, BoolConstraintGuards<'ctx>>,
}

impl<'ctx> SmtSampler<'ctx> {
    pub fn new(ctx: &'ctx Context, csts: Vec<Bool<'ctx>>) -> SmtSampler<'ctx> {
        let opt = z3::Optimize::new(&ctx);
        let original_tracking = csts.clone().into_iter().enumerate().map(|(idx,cst)| {
            let tracking = Bool::new_const(ctx, format!("{GUARD_PREFIX}original_{}", idx));
            opt.assert_and_track(&cst.clone().try_into().unwrap(), &tracking);
            (cst, tracking)
        }).collect();
        assert!(opt.timed_check_assumptions(&[]) == SatResult::Sat);

        SmtSampler {
            ctx,
            optimizer: opt,
            constraints: csts,
            original_constraint_guard_variables: original_tracking,
            soft_bit_constraint_guard_variables: HashMap::new(),
            soft_bool_constraint_guard_variables: HashMap::new()
        }
    }
    pub fn guards_for_bit(&mut self, var: BV<'ctx>, bit_idx: u32) -> BitConstraintGuards<'ctx> {
        self.soft_bit_constraint_guard_variables
            .entry((var.clone(), bit_idx))
            .or_insert_with(|| {
                BitConstraintGuards::create_bit_constraints(
                    self.ctx, &self.optimizer, &var, bit_idx
                )
            }).clone()
    }
    pub fn guards_for_bool(&mut self, var: Bool<'ctx>) -> BoolConstraintGuards<'ctx> {
        self.soft_bool_constraint_guard_variables
            .entry(var.clone())
            .or_insert_with(|| {
                BoolConstraintGuards::create_bool_constraints(
                    self.ctx, &self.optimizer, &var
                )
            }).clone()
    }
    pub fn baseline_soft_assumptions_for_model(&mut self, model: &SimpleModel<'ctx>) -> Vec<Bool<'ctx>> {
        let mut result = vec![];
        println!("Pushing assumptions!");
        for decl in model.bvs.keys() {

            result.append(&mut self.assert_var_equals_soft(decl, model));
        }
        for decl in model.bools.keys() {
            // println!("Pushing assumptions for {:?}", decl);
            result.append(&mut self.assert_var_equals_soft(&decl, model));
        }
        result
    }
    pub fn assert_var_equals_soft(
        &mut self,
        decl: &FuncDecl<'ctx>,
        model: &SimpleModel<'ctx>,
    ) -> Vec<Bool<'ctx>> {
        let sort = decl.range();
        let var = decl.apply(&[]);
        let result_guards = vec![];
        match sort.kind() {
            SortKind::BV => {
                let model_val = model.get_bv_val(decl);
                let ast_val= BV::from_u64(self.ctx, model_val, sort.bv_size().unwrap().try_into().unwrap());
                self.optimizer.assert_soft(&var._eq(&ast_val.into()), 1u64, None);
                // for i in 0..sort.bv_size().unwrap().try_into().unwrap() {
                //     let var_clone = var.clone().as_bv().unwrap();
                //     let guards = self.guards_for_bit(var_clone, i);
                //     let bitval = model.get_bit_val(&decl, i);
                //     result_guards.push( guards.get(soft, bitval) );
                // }
            },
            SortKind::Bool => {
                let model_val = model.get_bool_val(decl);
                self.optimizer.assert_soft(&var._eq(&Bool::from_bool(self.ctx, model_val).into()), 1u64, None)
                // result_guards.push(
                //     self
                //         .guards_for_bool(var.as_bool().unwrap())
                //         .get(soft, model.get_bool_val(&decl))
                // );
            },
            _ => todo!()
        };
        result_guards
    }
    pub fn possible_primitive_mutations_iter(& mut self, model: &SimpleModel<'ctx>) -> std::vec::IntoIter<PrimitiveMutationLocation<'ctx>> {
        let mut muts = vec![];
        let mut baseline_assumptions = vec![];
        for (decl, _) in model.bvs.iter() {
            println!("Pushing bit mutations for {:?}", decl);
            let bv_size = decl.range().bv_size().unwrap().try_into().unwrap();
            assert!(bv_size <= 64);
            for i in 0..bv_size {
                muts.push(PrimitiveMutationLocation::Bit { decl: decl.clone(), bit_idx: i})
            }
            baseline_assumptions.extend(self.assert_var_equals_soft(decl, model).into_iter());
        }
        for (decl, _) in model.bools.iter() {
            println!("Pushing bool mutations for {:?}", decl);
            muts.push(PrimitiveMutationLocation::Bool { decl: decl.clone() });
            baseline_assumptions.extend(self.assert_var_equals_soft(decl, model).into_iter());
        }
        let mut rng = thread_rng();
        println!("Shuffling...");
        muts.shuffle(&mut rng);
        muts.into_iter()
    }
    pub fn get_primitive_mutation(
        &mut self,
        model: &SimpleModel<'ctx>,
        baseline_assumptions: Vec<Bool<'ctx>>,
        loc: PrimitiveMutationLocation<'ctx>
    ) -> Option<ModelMutation<'ctx>> {
        println!("get_primitive_mutation({:?})", loc);
        let _mut = match loc {
            PrimitiveMutationLocation::Bit { decl, bit_idx} => {
                self.get_primitive_mutation_for_bit(model, baseline_assumptions, &decl, bit_idx).ok()
            },
            PrimitiveMutationLocation::Bool { decl } => {
                self.get_primitive_mutation_for_bool(model, baseline_assumptions, &decl).ok()
            }
        };
        println!("mutation: {:?}", _mut);
        _mut
    }
    pub fn get_primitive_mutation_for_bit (
        &mut self,
        model: &SimpleModel<'ctx>,
        baseline_assumptions: Vec<Bool<'ctx>>,
        var_decl: &FuncDecl<'ctx>,
        bit_to_flip: u32
    ) -> Result<ModelMutation<'ctx>, MutationFailed>
    {
        println!("get_primitive_mutation_for_bit({:?}, {:x})", var_decl, bit_to_flip);
        let _type = var_decl.range();
        assert!(_type.kind() == SortKind::BV);
        let var = var_decl.apply(&[]).as_bv().expect(&format!("somehow instantiating bv variable {:?} returns a non bv?", var_decl));

        let bv_size = _type.bv_size().expect(&format!("Could not retrieve bv size for {:?}!", &_type));
        assert!(bv_size <= 64, "we do not support bvs of size > 64, fix {:?}", &var_decl);

        let test_mut = ModelMutation::from(vec![(var.clone(), 1<<(bit_to_flip as u64))], vec![]);
        if test_mut.apply(model).satisfies_constraints(&self.original_constraint_guard_variables.keys().collect::<Vec<_>>()[..]) {
            return Ok(test_mut);
        }

        let guards = self.guards_for_bit(var.clone(), bit_to_flip);
        let bitval = model.get_bit_val(&var_decl, bit_to_flip);

        let mut baseline_assumptions = baseline_assumptions;
        // force the bit to flip, all soft constraints are already there
        baseline_assumptions.push(guards.get(false, !bitval));

        match self.optimizer.timed_check_assumptions(&baseline_assumptions.iter().collect::<Vec<_>>()[..]) {
            SatResult::Unknown => {
                Err(MutationFailed::SolverUnknown { reason: self.optimizer.get_reason_unknown() })
            },
            SatResult::Unsat => {
                Err(MutationFailed::SolverUnsat { core: self.optimizer.get_unsat_core() })
            },
            SatResult::Sat => {
                let cur_z3_model = self.optimizer.get_model()
                    .expect(&format!("We expect a model for sat results??? {:?}", self.optimizer));
                let cur_model = SimpleModel::from_model(&cur_z3_model);

                // println!("Model for different {:?}#{}: [{:?}]", &var, bit_to_flip, cur_model);
                let mutation = cur_model.minimal_mutation(&model);
                // println!("primitive mutation {:?}", mutation);
                Ok(mutation)
            }
        }
    }

    pub fn get_primitive_mutation_for_bool (
        &mut self,
        model: &SimpleModel<'ctx>,
        baseline_assumptions: Vec<Bool<'ctx>>,
        var_decl: &FuncDecl<'ctx>
    ) -> Result<ModelMutation<'ctx>, MutationFailed>
    {
        let _type = var_decl.range();
        assert!(_type.kind() == SortKind::Bool);

        let var = var_decl.apply(&[]).as_bool().expect(
            &format!("somehow instantiating bool variable {:?} returns a non bool expression?", var_decl)
        );

        let guards = self.guards_for_bool(var);
        let boolval = model.get_bool_val(&var_decl);

        let mut baseline_assumptions = baseline_assumptions;
        // force the bool to flip, all soft constraints are already there
        baseline_assumptions.push(guards.get(false, !boolval));

        match self.optimizer.timed_check_assumptions(&baseline_assumptions.iter().collect::<Vec<_>>()[..]) {
            SatResult::Unknown => {
                Err(MutationFailed::SolverUnknown { reason: self.optimizer.get_reason_unknown() })
            },
            SatResult::Unsat => {
                Err(MutationFailed::SolverUnsat { core: self.optimizer.get_unsat_core() })
            },
            SatResult::Sat => {
                let cur_z3_model = self.optimizer.get_model()
                    .expect(&format!("We expect a model for sat results??? {:?}", self.optimizer));
                let cur_model = SimpleModel::from_model(&cur_z3_model);

                // println!("Model for different {:?}#{}: [{:?}]", &var, bit_to_flip, cur_model);
                let mutation = cur_model.minimal_mutation(&model);
                // println!("primitive mutation {:?}", mutation);
                Ok(mutation)
            }
        }
    }

    pub fn get_all_primitive_mutations(
        &mut self,
        model: &SimpleModel<'ctx>,
        baseline_assumptions: Vec<Bool<'ctx>>
    ) -> Vec<ModelMutation<'ctx>>
    {
        self.possible_primitive_mutations_iter(model)
            .take(10)
            .filter_map(|loc| self.get_primitive_mutation(model, baseline_assumptions.clone(), loc))
            .collect()
    }

    pub fn quick_sample(&mut self) -> Vec<SimpleModel> {
        warn!("TODO: implement multiple epochs starting with fresh models instead of just one epoch");

        let original_model = SimpleModel::from_model(&self.optimizer.get_model().expect("We expect to always get a model??"));
        println!("original model: {:?}", original_model);

        let soft_equal_assumptions = self.baseline_soft_assumptions_for_model(&original_model);
        println!("Got soft assumptions");
        let min_muts = self.get_all_primitive_mutations(&original_model, soft_equal_assumptions);
        println!("Discovered mutations: ");
        min_muts.iter().for_each(|x| {
            println!("\t{:?}", x);
        });

        let mut all_mutations: SortedSet<ModelMutation<'ctx>> = min_muts.clone()
            .into_iter()
            .collect::<Vec<_>>()
            .into();

        let mut all_solutions: Vec<SimpleModel<'ctx>> = min_muts
            .iter()
            .map(|mutation| mutation.apply(&original_model))
            .chain([original_model.clone()].into_iter())
            .collect::<Vec<_>>();

        warn!("TODO: implement backoff on too many invalid solutions, restart epoch. See SMTSampler paper");
        let mut mut_succ = vec![];
        for k in 0..6 {
            println!("k: {}", k);
            let derivative_mutations = all_mutations
                .iter()
                .cartesian_product(min_muts.iter())
                .collect::<Vec<_>>();
            let mut new_valid_mutations = vec![];
            let (mut mut_success, mut mut_new, mut mut_total) = (0, 0, 0);
            for (old, new) in derivative_mutations {

                let new_mut = old.combine(new);

                let new_model = new_mut.apply(&original_model);
                if all_mutations.contains(&new_mut) {
                    continue;
                }

                if new_model.satisfies_constraints(&self.constraints[..].iter().collect::<Vec<_>>()[..]) {
                    // println!("Discovered new VALID mutation! {:?}, resulting in {:?}", new_mut, &new_model);
                    println!("Discovered new VALID mutation! {:?}", new_mut);
                    mut_success += 1;
                    if !all_solutions.contains(&new_model) {
                        all_solutions.push(new_model);
                        mut_new += 1;
                    }
                    new_valid_mutations.push(new_mut);
                }
                mut_total += 1;
                // else {
                //     println!("Discovered new INVALID mutation! {:?}, resulting in {:?}", new_mut, &new_model);
                // }
            }
            println!("new valid: {:?}", new_valid_mutations);
            mut_succ.push((mut_new, mut_success, mut_total));
            if new_valid_mutations.len() > 0 {
                all_mutations.extend(new_valid_mutations.into_iter());
            }
            else {
                break;
            }
        }
        println!("Statistics: {:?}", mut_succ);
        all_solutions.into_iter().sorted().collect()
    }

}


const INPUT_BYTE_PREFIX : &str = "INPUT_BYTE_";
pub fn get_input_byte_var(idx: u64) -> String {
    return format!("{}_{:x}", INPUT_BYTE_PREFIX, idx);
}

pub fn get_input_byte_index(name: &str) -> Option<u64> {
    assert!(name.starts_with(INPUT_BYTE_PREFIX));
    let num_slice = &name[INPUT_BYTE_PREFIX.len()+1..];
    match u64::from_str_radix(num_slice, 16) {
        Ok(value) => Some(value),
        Err(_) => None
    }
}