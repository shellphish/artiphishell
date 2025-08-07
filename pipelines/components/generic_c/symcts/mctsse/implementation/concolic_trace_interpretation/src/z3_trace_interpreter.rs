use log;

use itertools::Itertools;
// use libafl::observers::concolic::{SymExpr, SymExprRef, SymbolicAddressDereferenceMetadata};
use libafl::observers::concolic::{SymExpr, SymExprRef};
use z3::ast::{Dynamic, BV, Bool, Ast};

use crate::{ConcolicTraceInterpreter, ConstraintToMutate, ConstraintMutationSource};

pub struct Z3TraceInterpreter<'z3_ctx> {
    z3_ctx: &'z3_ctx z3::Context,
    input_vars: Vec<BV<'z3_ctx>>,
    enforce_concretization: bool,
    solve_for_concretization_alternatives: bool,

    msgs: Vec<(SymExprRef, SymExpr)>,
    translation: Vec<Dynamic<'z3_ctx>>,
    mutation_sources: Vec<ConstraintMutationSource>,
    constraints_for_mutation: Vec<ConstraintToMutate<Bool<'z3_ctx>>>,
}

impl<'z3_ctx> Z3TraceInterpreter<'z3_ctx> {
    pub fn new(z3_ctx: &'z3_ctx z3::Context) -> Self {
        Self {
            z3_ctx,
            input_vars: Vec::new(),
            enforce_concretization: false,
            solve_for_concretization_alternatives: false,

            msgs: Vec::new(),
            translation: Vec::new(),
            mutation_sources: Vec::new(),
            constraints_for_mutation: Vec::new(),
        }
    }
    pub fn enforce_concretization(mut self, val: bool) -> Self {
        self.enforce_concretization = val;
        self
    }
    pub fn solve_for_concretization_alternatives(mut self, val: bool) -> Self {
        self.solve_for_concretization_alternatives = val;
        self
    }
    pub fn input_vars(&self) -> &[BV<'z3_ctx>] {
        &self.input_vars
    }
}

impl<'z3_ctx> ConcolicTraceInterpreter for Z3TraceInterpreter<'z3_ctx> {
    type BoolType = Bool<'z3_ctx>;
    type BVType = BV<'z3_ctx>;

    fn as_bool(&self, op: SymExprRef) -> Self::BoolType {
        self.as_bool_inner(op)
    }

    fn as_bv(&self, op: SymExprRef) -> Self::BVType {
        self.as_bv_inner(op)
    }

    fn unique_constraints_iter(&self) -> impl Iterator<Item = &ConstraintToMutate<Self::BoolType>> {
        self.unique_constraints_iter_inner()
    }

    fn interpret_message(&mut self, id: SymExprRef, msg: SymExpr) {
        self.interpret_message_inner(id, msg)
    }
}

impl<'z3_ctx> Z3TraceInterpreter<'z3_ctx> {
    fn as_bool_inner(&self, op: SymExprRef) -> Bool<'z3_ctx> {
        if let Some(bool_val) = self.translation[op.get() - 1].as_bool() {
            bool_val
        } else {
            let bv = self.translation[op.get() - 1].as_bv().unwrap();
            let sz = bv.get_size();
            assert!(sz == 1, "_self.as_bool() called on non-bool expr: {:?} of size {}", bv, sz);
            bv._eq(&BV::from_i64(bv.get_ctx(), 0, sz)).not()
        }
    }

    fn as_bv_inner(&self, op: SymExprRef) -> BV<'z3_ctx> {
        match self.translation[op.get() - 1].as_bv() {
            Some(bv) => bv,
            None => {
                let bool_val = self.translation[op.get() - 1].as_bool().unwrap();
                bool_val.ite(&BV::from_i64(bool_val.get_ctx(), 1, 1), &BV::from_i64(bool_val.get_ctx(), 0, 1))
            }
        }
    }

    fn unique_constraints_iter_inner(&self) -> impl Iterator<Item = &ConstraintToMutate<Bool<'z3_ctx>>> {
        self.constraints_for_mutation
            .iter()
            .unique_by(|x| x.key)
    }

    pub fn constraints_for_mutation(&self) -> &[ConstraintToMutate<Bool<'z3_ctx>>] {
        &self.constraints_for_mutation
    }
    fn build_symbolic_read_ite_tree(
        &mut self,
        sym_address: &BV<'z3_ctx>,
        values_start_address: usize,
        values: Vec<(u8, BV<'z3_ctx>)>,
    ) -> BV<'z3_ctx> {
        if values.len() == 1 {
            let (conc_value, sym_value) = values.first().unwrap();
            return sym_value.clone();
        }
        let mid = values.len() / 2;
        let (left, right) = values.split_at(mid);
        let mid_address = values_start_address + mid;
        let mid_address_bv = BV::from_u64(self.z3_ctx, mid_address as u64, usize::BITS as u32);

        let bv_left = self.build_symbolic_read_ite_tree(sym_address, values_start_address, left.to_vec());
        let bv_right = self.build_symbolic_read_ite_tree(sym_address, mid_address, right.to_vec());

        let sym_address_lt_mid = sym_address.bvult(&mid_address_bv);

        return sym_address_lt_mid.ite(&bv_left, &bv_right);
    }

    fn interpret_message_inner(&mut self, id: SymExprRef, msg: SymExpr) {
        let mut _self = self;
        let z3_ctx = _self.z3_ctx;

        macro_rules! bv_binop {
            ($a:ident $op:tt $b:ident) => {
                Some(_self.as_bv($a).$op(&_self.as_bv($b)).into())
            };
        }
        _self.msgs.push((id, msg));
        let (id, msg) = _self.msgs.last().unwrap();
        let id = *id;
        let msg = msg.clone();
        // log::debug!(target: "symcts::interpreted_trace", "interpreting message {:x} => {:?}", id.get(), msg);
        // println!("symcts::interpreted_trace: interpreting message {:x} => {:?}", id.get(), msg);
        let z3_expr: Option<Dynamic> = match msg {
            SymExpr::PathConstraint { constraint, taken, location } => {
                let mutation_source = ConstraintMutationSource::PathConstraint {
                    expr: constraint, taken: taken, location: location
                };
                let cst_expr = _self.as_bool(constraint).simplify();
                let cst_expr_not = cst_expr.not().simplify();
                let (expr_taken, expr_divergent) = if taken {
                    (cst_expr, cst_expr_not)
                }
                else {
                    (cst_expr_not, cst_expr)
                };

                let cst_guard_taken = Bool::new_const(z3_ctx, format!("path_constraint_0x{:x}_taken_{:x?}", constraint.get(), location));
                let cst_guard_divergent = Bool::new_const(z3_ctx, format!("path_constraint_0x{:x}_divergent_{:x?}", constraint.get(), location));

                _self.mutation_sources.push(mutation_source.clone());
                _self.constraints_for_mutation.push(
                    ConstraintToMutate {
                        is_divergent: true,
                        source: (mutation_source.clone(), 0),
                        constraint: expr_divergent,
                        constraint_guard: cst_guard_divergent,
                        location: location.clone(),
                        key: (constraint.get(), 0),
                    });
                _self.constraints_for_mutation.push(
                    ConstraintToMutate {
                        is_divergent: false,
                        source: (mutation_source.clone(), 1),
                        constraint: expr_taken,
                        constraint_guard: cst_guard_taken,
                        location: location.clone(),
                        key: (constraint.get(), 1),
                    });
                None
            },
            SymExpr::ConcretizePointer { expr, value, location }
            | SymExpr::ConcretizeSize { expr, value, location } => {
                if _self.enforce_concretization || _self.solve_for_concretization_alternatives
                {
                    let mutation_source = match msg {
                        SymExpr::ConcretizePointer { expr, value, location } => {
                            ConstraintMutationSource::ConcretizePointer {
                                expr: expr, value: value, location: location
                            }
                        },
                        SymExpr::ConcretizeSize { expr, value, location } => {
                            ConstraintMutationSource::ConcretizeSize {
                                expr: expr, value: value, location: location
                            }
                        },
                        _ => unreachable!()
                    };
                    let val_expr = _self.as_bv(expr).simplify();

                    if _self.solve_for_concretization_alternatives {
                        let lt_cst = val_expr.bvult(&BV::from_u64(&z3_ctx, value as u64, usize::BITS.try_into().unwrap())).simplify();
                        let gt_cst = val_expr.bvugt( &BV::from_u64(&z3_ctx, value as u64, usize::BITS.try_into().unwrap())).simplify();
                        let lt_guard = Bool::new_const(&z3_ctx, format!("concretize_pointer_0x{:x}_divergent_lt_{:x?}", expr.get(), location));
                        let gt_guard = Bool::new_const(&z3_ctx, format!("concretize_pointer_0x{:x}_divergent_gt_{:x?}", expr.get(), location));
                        _self.constraints_for_mutation.push(
                            ConstraintToMutate {
                                is_divergent: true,
                                source: (mutation_source.clone(), 0),
                                constraint: lt_cst,
                                constraint_guard: lt_guard,
                                location: location.clone(),
                                key: (expr.get(), 0),
                            });

                        _self.constraints_for_mutation.push(
                            ConstraintToMutate {
                                is_divergent: true,
                                source: (mutation_source.clone(), 1),
                                constraint: gt_cst,
                                constraint_guard: gt_guard,
                                location: location.clone(),
                                key: (expr.get(), 1),
                            });
                    }

                    if _self.enforce_concretization {
                        let eq_cst = val_expr._eq(&BV::from_u64(&z3_ctx, value as u64, usize::BITS.try_into().unwrap())).simplify();
                        let eq_guard = Bool::new_const(&z3_ctx, format!("concretize_pointer_0x{:x}_eq_{:x?}", expr.get(), location));

                        _self.constraints_for_mutation.push(
                            ConstraintToMutate {
                                is_divergent: false,
                                source: (mutation_source.clone(), 2),
                                constraint: eq_cst,
                                constraint_guard: eq_guard,
                                location: location.clone(),
                                key: (expr.get(), 2),
                            });
                    }
                }
                None
            },

            SymExpr::InputByte { offset, .. } => {
                // assert!(next_var_index <= offset);
                // next_var_index = offset + 1;
                let var = BV::new_const(z3_ctx, format!("k!{}", offset * 10), 8);
                _self.input_vars.push(var.clone());
                Some(var.into())
            }
            SymExpr::Integer { value, bits } => {
                Some(BV::from_u64(z3_ctx, value, bits.try_into().unwrap()).into())
            }
            SymExpr::Integer128 { high: _, low: _ } => todo!(),
            SymExpr::NullPointer => {
                Some(BV::from_u64(z3_ctx, 0, usize::BITS.try_into().unwrap()).into())
            }
            SymExpr::True => Some(Bool::from_bool(z3_ctx, true).into()),
            SymExpr::False => Some(Bool::from_bool(z3_ctx, false).into()),
            SymExpr::Bool { value } => Some(Bool::from_bool(z3_ctx, value).into()),
            SymExpr::Neg { op } => Some(_self.as_bv(op).bvneg().into()),
            SymExpr::Add { a, b } => bv_binop!(a bvadd b),
            SymExpr::Sub { a, b } => bv_binop!(a bvsub b),
            SymExpr::Mul { a, b } => bv_binop!(a bvmul b),
            SymExpr::UnsignedDiv { a, b } => bv_binop!(a bvudiv b),
            SymExpr::SignedDiv { a, b } => bv_binop!(a bvsdiv b),
            SymExpr::UnsignedRem { a, b } => bv_binop!(a bvurem b),
            SymExpr::SignedRem { a, b } => bv_binop!(a bvsrem b),
            SymExpr::ShiftLeft { a, b } => bv_binop!(a bvshl b),
            SymExpr::LogicalShiftRight { a, b } => bv_binop!(a bvlshr b),
            SymExpr::ArithmeticShiftRight { a, b } => bv_binop!(a bvashr b),
            SymExpr::SignedLessThan { a, b } => bv_binop!(a bvslt b),
            SymExpr::SignedLessEqual { a, b } => bv_binop!(a bvsle b),
            SymExpr::SignedGreaterThan { a, b } => bv_binop!(a bvsgt b),
            SymExpr::SignedGreaterEqual { a, b } => bv_binop!(a bvsge b),
            SymExpr::UnsignedLessThan { a, b } => bv_binop!(a bvult b),
            SymExpr::UnsignedLessEqual { a, b } => bv_binop!(a bvule b),
            SymExpr::UnsignedGreaterThan { a, b } => bv_binop!(a bvugt b),
            SymExpr::UnsignedGreaterEqual { a, b } => bv_binop!(a bvuge b),
            SymExpr::Not { op } => {
                let translated = &_self.translation[op.get() - 1];
                Some(if let Some(bv) = translated.as_bv() {
                    bv.bvnot().into()
                } else if let Some(bool) = translated.as_bool() {
                    bool.not().into()
                } else {
                    panic!(
                        "unexpected z3 expr of type {:?} when applying not operation",
                        translated.kind()
                    )
                })
            }
            SymExpr::Equal { a, b } => Some(_self.translation[a.get() - 1]._eq(&_self.translation[b.get() - 1]).into()),
            SymExpr::NotEqual { a, b } => Some(_self.translation[a.get() - 1]._eq(&_self.translation[b.get() - 1]).not().into()),
            SymExpr::BoolAnd { a, b } => Some(Bool::and(z3_ctx, &[&_self.as_bool(a), &_self.as_bool(b)]).into()),
            SymExpr::BoolOr { a, b } => Some(Bool::or(z3_ctx, &[&_self.as_bool(a), &_self.as_bool(b)]).into()),
            SymExpr::BoolXor { a, b } => Some(_self.as_bool(a).xor(&_self.as_bool(b)).into()),
            SymExpr::And { a, b } => bv_binop!(a bvand b),
            SymExpr::Or { a, b } => bv_binop!(a bvor b),
            SymExpr::Xor { a, b } => bv_binop!(a bvxor b),
            SymExpr::Sext { op, bits } => Some(_self.as_bv(op).sign_ext(u32::from(bits)).into()),
            SymExpr::Zext { op, bits } => Some(_self.as_bv(op).zero_ext(u32::from(bits)).into()),
            SymExpr::Trunc { op, bits } => Some(_self.as_bv(op).extract(u32::from(bits - 1), 0).into()),
            SymExpr::BoolToBit { op } => Some(
                _self.as_bool(op)
                    .ite(
                        &BV::from_u64(z3_ctx, 1, 1),
                        &BV::from_u64(z3_ctx, 0, 1),
                    )
                    .into(),
            ),
            SymExpr::Concat { a, b } => bv_binop!(a concat b),
            SymExpr::Extract {
                op,
                first_bit,
                last_bit,
            } => Some(_self.as_bv(op).extract(first_bit as u32, last_bit as u32).into()),
            SymExpr::Insert {
                target,
                to_insert,
                offset,
                little_endian,
            } => {
                let target = _self.as_bv(target);
                let to_insert = _self.as_bv(to_insert);
                let bits_to_insert: u64 = to_insert.get_size().try_into().unwrap();
                assert_eq!(bits_to_insert % 8, 0, "can only insert full bytes");
                let target_size: u64 = target.get_size().try_into().unwrap();
                let after_len = (target_size / 8) - offset - (bits_to_insert / 8);
                Some(
                    [
                        if offset == 0 {
                            None
                        } else {
                            Some(build_extract(&target, 0, offset, false))
                        },
                        Some(if little_endian {
                            build_extract(&to_insert, 0, bits_to_insert / 8, true)
                        } else {
                            to_insert
                        }),
                        if after_len == 0 {
                            None
                        } else {
                            Some(build_extract(
                                &target,
                                offset + (bits_to_insert / 8),
                                after_len,
                                false,
                            ))
                        },
                    ]
                    .into_iter()
                    .reduce(|acc: Option<BV>, val: Option<BV>| match (acc, val) {
                        (Some(prev), Some(next)) => Some(prev.concat(&next)),
                        (Some(prev), None) => Some(prev),
                        (None, next) => next,
                    })
                    .unwrap()
                    .unwrap()
                    .into(),
                )
            },
            // SymExpr::SymbolicMemoryRead { address_expr, value_read_expr, length, .. } => {
            //     let symbolized_mem_value = match address_expr {
            //         Some(
            //             (sym_addr,
            //                 SymbolicAddressDereferenceMetadata::KnownBoundDataAvailable {
            //                 bound_type,
            //                 min_addr,
            //                 max_addr,
            //                 touched_data_concrete,
            //                 touched_data_symbolic
            //             })) => {
            //                 // symbolic address, build ite tree.
            //                 // TODO: handle different bound types
            //                 assert!(touched_data_concrete.len() == touched_data_symbolic.len());
            //                 assert!(touched_data_concrete.len() == max_addr - min_addr + length);
            //                 let values = touched_data_concrete
            //                     .into_iter()
            //                     .zip(
            //                         touched_data_symbolic
            //                             .into_iter()
            //                         )
            //                     .map(|(val, expr)| {
            //                         let bv_expr = expr.map(|expr| _self.as_bv(expr)).unwrap_or_else(|| BV::from_u64(z3_ctx, val as u64, 8));
            //                         (val, bv_expr)
            //                     })
            //                     .collect();

            //                 let result = _self.build_symbolic_read_ite_tree(
            //                     &_self.as_bv(sym_addr),
            //                     min_addr,
            //                     values,
            //                 ).into();

            //                 Some(result)
            //             },
            //             _ => None
            //     };
            //     match (symbolized_mem_value, value_read_expr) {
            //         (Some(sym_value), _) => Some(sym_value),
            //         (None, Some(value_read_expr)) => Some(_self.as_bv(value_read_expr).into()),
            //         (None, None) => None,
            //     }
            // },
            _ => None,
        };
        if let Some(expr) = z3_expr {
            // println!("Inserting expression {:x} => {}", id, expr);
            assert!(_self.translation.len() == id.get() - 1, "translation is not in order: expected {}, got {}", _self.translation.len(), id.get() - 1);
            _self.translation.push(expr);
        }
    }
}

fn build_extract<'ctx>(
    bv: &BV<'ctx>,
    offset: u64,
    length: u64,
    little_endian: bool,
) -> BV<'ctx> {
    let size: u64 = bv.get_size().try_into().unwrap();
    assert_eq!(
        size % 8,
        0,
        "can't extract on byte-boundary on BV that is not byte-sized"
    );

    if little_endian {
        (0..length)
            .map(|i| {
                bv.extract(
                    (size - (offset + i) * 8 - 1).try_into().unwrap(),
                    (size - (offset + i + 1) * 8).try_into().unwrap(),
                )
            })
            .reduce(|acc, next| next.concat(&acc))
            .unwrap()
    } else {
        bv.extract(
            (size - offset * 8 - 1).try_into().unwrap(),
            (size - (offset + length) * 8).try_into().unwrap(),
        )
    }
}
