use std::{ffi::c_void, ops::{Add, BitAnd, BitOr}};

use symcc_runtime::{export_runtime, Runtime};
use z3::ast::{Ast, Bool, BV, Float, Dynamic};

pub enum CoverageAction<'ctx> {
    PathConstraintAdded {
        constraint: Bool<'ctx>,
        site_id: usize,
        taken: bool
    },
    Call {
        site_id: usize,
    },
    Return {
        site_id: usize,
    },
    BasicBlock {
        site_id: usize,
    },
}

pub struct MyRuntime<'ctx> {
    context: &'ctx z3::Context,
    expressions: Vec<Dynamic<'ctx>>,
    path_constraints: Vec<Bool<'ctx>>,
    coverage_actions: Vec<CoverageAction<'ctx>>,
}
impl<'ctx> MyRuntime<'ctx> {
    fn new(context: &'ctx z3::Context) -> Self {
        Self {
            context,
            expressions: Vec::new(),
            path_constraints: Vec::new(),
            coverage_actions: Vec::new(),
        }
    }
    fn register(&mut self, expression: Dynamic<'ctx>) -> Option<RSymExpr>{
        self.expressions.push(expression);
        Some(RSymExpr::new(self.expressions.len()).unwrap())
    }
    fn retrieve(&mut self, reference: RSymExpr) -> Dynamic<'ctx> {
        self.expressions.get(reference.get() - 1).unwrap().clone()
    }
}

macro_rules! z3_binop {
    ($ty:ident, $t:ident, $s:ident) => {
        fn $t(&mut self, a: RSymExpr, b: RSymExpr) -> Option<RSymExpr> {
            let lhs: $ty<'ctx> = self.retrieve(a).try_into().unwrap();
            let rhs: $ty<'ctx> = self.retrieve(b).try_into().unwrap();
            self.register(lhs.$s(&rhs).into())
        }
    };
}

impl<'ctx> Runtime for MyRuntime<'ctx> {

    fn build_integer(&mut self, value: u64, bits: u8) -> Option<RSymExpr> {
        let expr = BV::from_u64(self.context, value, bits as usize);
        self.register(expr.into())
    }

    fn build_integer128(&mut self, high: u64, low: u64) -> Option<RSymExpr> {

        let expr =
            BV::from_u64(self.context, high, 64)
                .concat(&BV::from_u64(self.context, low, 64));

        self.register(expr.into())
    }

    fn build_float(&mut self, value: f64, is_double: bool) -> Option<RSymExpr> {
        let expr = if is_double {
            Float::from_f64(self.context, value)
        } else {
            todo!()
        };
        self.register(expr.into())
    }

    fn build_null_pointer(&mut self) -> Option<RSymExpr> {
        let expr = BV::from_u64(self.context, 0, std::mem::size_of::<*const c_void>());
        self.register(expr.into())
    }

    fn build_true(&mut self) -> Option<RSymExpr> {
        self.register(Bool::from_bool(self.context, true).into())
    }

    fn build_false(&mut self) -> Option<RSymExpr> {
        self.register(Bool::from_bool(self.context, false).into())
    }

    fn build_bool(&mut self, value: bool) -> Option<RSymExpr> {
        self.register(Bool::from_bool(self.context, value).into())
    }

    fn build_not(&mut self, op: RSymExpr) -> Option<RSymExpr> {
        let expr: BV<'ctx> = self.retrieve(op).try_into().unwrap();
        self.register(expr.bvnot().into())
    }

    fn build_neg(&mut self, expr: RSymExpr) -> Option<RSymExpr> {
        let val: BV<'ctx> = self.retrieve(expr).try_into().unwrap();
        self.register(val.bvneg().into())
    }

    z3_binop!(BV, build_add, bvadd);
    z3_binop!(BV, build_sub, bvsub);
    z3_binop!(BV, build_mul, bvmul);
    z3_binop!(BV, build_unsigned_div, bvudiv);
    z3_binop!(BV, build_signed_div, bvsdiv);
    z3_binop!(BV, build_unsigned_rem, bvurem);
    z3_binop!(BV, build_signed_rem, bvsrem);

    z3_binop!(BV, build_or, bvor);
    z3_binop!(BV, build_and, bvand);
    z3_binop!(BV, build_xor, bvxor);

    z3_binop!(BV, build_shift_left, bvshl);
    z3_binop!(BV, build_logical_shift_right, bvlshr);
    z3_binop!(BV, build_arithmetic_shift_right, bvashr);

    z3_binop!(BV, build_signed_less_than, bvslt);
    z3_binop!(BV, build_signed_less_equal, bvsle);
    z3_binop!(BV, build_signed_greater_than, bvsgt);
    z3_binop!(BV, build_signed_greater_equal, bvsge);
    z3_binop!(BV, build_unsigned_less_than, bvult);
    z3_binop!(BV, build_unsigned_less_equal, bvule);
    z3_binop!(BV, build_unsigned_greater_than, bvugt);
    z3_binop!(BV, build_unsigned_greater_equal, bvuge);
    z3_binop!(BV, build_equal, _eq);

    fn build_not_equal(&mut self, a: RSymExpr, b: RSymExpr) -> Option<RSymExpr> {
        let a: BV<'ctx> = self.retrieve(a).try_into().unwrap();
        let b: BV<'ctx> = self.retrieve(b).try_into().unwrap();
        self.register(a._eq(&b).not().into())
    }


    z3_binop!(Bool, build_bool_and, bitand);
    z3_binop!(Bool, build_bool_or, bitor);
    z3_binop!(Bool, build_bool_xor, xor);

    fn build_sext(&mut self, expr: RSymExpr, bits: u8) -> Option<RSymExpr> {
        let expr: BV<'ctx> = self.retrieve(expr).try_into().unwrap();
        let cur_bv_size = expr.get_size();
        assert!(cur_bv_size <= bits as usize);
        assert!(bits == 8 || bits == 16 || bits == 32 || bits == 64 || bits == 128);
        let to_extend = bits as usize - cur_bv_size;
        let res = expr.sign_ext(to_extend.try_into().unwrap());
        self.register(res.into())
    }

    fn build_zext(&mut self, expr: RSymExpr, bits: u8) -> Option<RSymExpr> {
        let expr: BV<'ctx> = self.retrieve(expr).try_into().unwrap();
        let cur_bv_size = expr.get_size();
        assert!(cur_bv_size <= bits as usize);
        assert!(bits == 8 || bits == 16 || bits == 32 || bits == 64 || bits == 128);
        let to_extend = bits as usize - cur_bv_size;
        let res = expr.zero_ext(to_extend.try_into().unwrap());
        self.register(res.into())
    }

    fn build_bool_to_bits(&mut self, expr: RSymExpr, bits: u8) -> Option<RSymExpr> {
        let expr: Bool<'ctx> = self.retrieve(expr).try_into().unwrap();
        let expr_true = BV::from_u64(self.context, 1, bits as usize);
        let expr_false = BV::from_u64(self.context, 0, bits as usize);
        let res = expr.ite(&expr_true, &expr_false);
        self.register(res.into())
    }

    fn concat_helper(&mut self, a: RSymExpr, b: RSymExpr) -> Option<RSymExpr> {
        let a: BV<'ctx> = self.retrieve(a).try_into().unwrap();
        let b: BV<'ctx> = self.retrieve(b).try_into().unwrap();
        self.register(a.concat(&b).into())
    }

    fn extract_helper(
        &mut self,
        expr: RSymExpr,
        first_bit: usize,
        last_bit: usize,
    ) -> Option<RSymExpr> {
        let expr: BV<'ctx> = self.retrieve(expr).try_into().unwrap();
        // I verified that this is how the indices work! extract_helper(expr, 7, 0) == lowest byte of expr
        let res = expr.extract(first_bit as u32, last_bit as u32);
        self.register(res.into())
    }

    fn build_trunc(&mut self, expr: RSymExpr, bits: u8) -> Option<RSymExpr> {
        assert!(bits != 0);
        let expr: BV<'ctx> = self.retrieve(expr).try_into().unwrap();
        self.register(expr.extract((bits - 1) as u32, 0).into())
    }

    fn push_path_constraint(&mut self, constraint: RSymExpr, taken: bool, site_id: usize) {
        let expr: Bool<'ctx> = self.retrieve(constraint).try_into().unwrap();
        let path_constraint = if taken {
            expr.clone()
        } else {
            expr.not()
        };
        self.path_constraints.push(path_constraint);
        self.coverage_actions.push(CoverageAction::PathConstraintAdded {
            constraint: expr,
            site_id: site_id,
            taken: taken
        })
    }

    fn get_input_byte(&mut self, offset: usize) -> Option<RSymExpr> {
        let expr = BV::new_const(self.context, format!("k!{}", offset), 8);
        self.register(expr.into())
    }

    fn notify_call(&mut self, site_id: usize) {
        self.coverage_actions.push(
            CoverageAction::Call {
                site_id: site_id,
            }
        )
    }

    fn notify_ret(&mut self, site_id: usize) {
        self.coverage_actions.push(
            CoverageAction::Return {
                site_id: site_id,
            }
        )
    }

    fn notify_basic_block(&mut self, site_id: usize) {
        self.coverage_actions.push(
            CoverageAction::BasicBlock {
                site_id: site_id,
            }
        )
    }

    fn expression_unreachable(&mut self, exprs: &[RSymExpr]) {
        todo!()
    }

    fn build_fp_add(&mut self, a: RSymExpr, b: RSymExpr) -> Option<RSymExpr> {
        todo!()
    }

    fn build_fp_sub(&mut self, a: RSymExpr, b: RSymExpr) -> Option<RSymExpr> {
        todo!()
    }

    fn build_fp_mul(&mut self, a: RSymExpr, b: RSymExpr) -> Option<RSymExpr> {
        todo!()
    }

    fn build_fp_div(&mut self, a: RSymExpr, b: RSymExpr) -> Option<RSymExpr> {
        todo!()
    }

    fn build_fp_rem(&mut self, a: RSymExpr, b: RSymExpr) -> Option<RSymExpr> {
        todo!()
    }

    fn build_fp_abs(&mut self, a: RSymExpr) -> Option<RSymExpr> {
        todo!()
    }

    fn build_float_ordered_greater_than(&mut self, a: RSymExpr, b: RSymExpr) -> Option<RSymExpr> {
        todo!()
    }

    fn build_float_ordered_greater_equal(&mut self, a: RSymExpr, b: RSymExpr) -> Option<RSymExpr> {
        todo!()
    }

    fn build_float_ordered_less_than(&mut self, a: RSymExpr, b: RSymExpr) -> Option<RSymExpr> {
        todo!()
    }

    fn build_float_ordered_less_equal(&mut self, a: RSymExpr, b: RSymExpr) -> Option<RSymExpr> {
        todo!()
    }

    fn build_float_ordered_equal(&mut self, a: RSymExpr, b: RSymExpr) -> Option<RSymExpr> {
        todo!()
    }

    fn build_float_ordered_not_equal(&mut self, a: RSymExpr, b: RSymExpr) -> Option<RSymExpr> {
        todo!()
    }

    fn build_float_ordered(&mut self, a: RSymExpr, b: RSymExpr) -> Option<RSymExpr> {
        todo!()
    }

    fn build_float_unordered(&mut self, a: RSymExpr, b: RSymExpr) -> Option<RSymExpr> {
        todo!()
    }

    fn build_float_unordered_greater_than(&mut self, a: RSymExpr, b: RSymExpr) -> Option<RSymExpr> {
        todo!()
    }

    fn build_float_unordered_greater_equal(
        &mut self,
        a: RSymExpr,
        b: RSymExpr,
    ) -> Option<RSymExpr> {
        todo!()
    }

    fn build_float_unordered_less_than(&mut self, a: RSymExpr, b: RSymExpr) -> Option<RSymExpr> {
        todo!()
    }

    fn build_float_unordered_less_equal(&mut self, a: RSymExpr, b: RSymExpr) -> Option<RSymExpr> {
        todo!()
    }

    fn build_float_unordered_equal(&mut self, a: RSymExpr, b: RSymExpr) -> Option<RSymExpr> {
        todo!()
    }

    fn build_float_unordered_not_equal(&mut self, a: RSymExpr, b: RSymExpr) -> Option<RSymExpr> {
        todo!()
    }



    fn build_int_to_float(
        &mut self,
        value: RSymExpr,
        is_double: bool,
        is_signed: bool,
    ) -> Option<RSymExpr> {
        todo!()
    }

    fn build_float_to_float(&mut self, expr: RSymExpr, to_double: bool) -> Option<RSymExpr> {
        todo!()
    }

    fn build_bits_to_float(&mut self, expr: RSymExpr, to_double: bool) -> Option<RSymExpr> {
        todo!()
    }

    fn build_float_to_bits(&mut self, expr: RSymExpr) -> Option<RSymExpr> {
        todo!()
    }

    fn build_float_to_signed_integer(&mut self, expr: RSymExpr, bits: u8) -> Option<RSymExpr> {
        todo!()
    }

    fn build_float_to_unsigned_integer(&mut self, expr: RSymExpr, bits: u8) -> Option<RSymExpr> {
        todo!()
    }
}

export_runtime!(MyRuntime::new(todo!()) => MyRuntime);

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
