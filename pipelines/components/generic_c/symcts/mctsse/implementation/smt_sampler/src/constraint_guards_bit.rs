use z3::{AstKind, Context, Optimize};
use z3::ast::{Bool, BV, Ast};

use crate::{GUARD_PREFIX, Guard};

pub struct BitConstraintGuards<'ctx> {
    ctx: &'ctx Context,
    soft_0: Guard<'ctx>,
    soft_1: Guard<'ctx>,
    hard_0: Guard<'ctx>,
    hard_1: Guard<'ctx>,
}
impl<'ctx> Clone for BitConstraintGuards<'ctx> {
    fn clone(&self) -> Self {
        BitConstraintGuards {
            ctx: self.ctx,
            soft_0: self.soft_0.clone(),
            soft_1: self.soft_1.clone(),
            hard_0: self.hard_0.clone(),
            hard_1: self.hard_1.clone()
        }
    }
}
impl <'ctx> BitConstraintGuards<'ctx> {
    pub fn create_bit_constraints(ctx: &'ctx Context, opt: &Optimize<'ctx>, var: &BV<'ctx>, bit_idx: u32) -> BitConstraintGuards<'ctx> {
        assert!(var.kind() == AstKind::App && var.is_const()); // constant values would be AstKind::Numeral instead, so this is only variables
        let var_name = var.decl().name();

        let soft_one = Bool::new_const(ctx,format!("{GUARD_PREFIX}soft_BV__{var_name}_{bit_idx}__is_1"));
        let hard_one = Bool::new_const(ctx,format!("{GUARD_PREFIX}hard_BV__{var_name}_{bit_idx}__is_1"));
        let hard_track_0 = Bool::new_const(ctx,format!("{GUARD_PREFIX}track_hard_BV__{var_name}_{bit_idx}__is_0"));
        let hard_track_1 = Bool::new_const(ctx,format!("{GUARD_PREFIX}track_hard_BV__{var_name}_{bit_idx}__is_1"));
        let guards = BitConstraintGuards {
            ctx,
            soft_0: soft_one.not(),
            soft_1: soft_one,
            hard_0: hard_one.not(),
            hard_1: hard_one
        };

        let const_bit_0 = BV::from_i64(ctx, 0, 1);
        let const_bit_1 = BV::from_i64(ctx, 1, 1);
        let ext = var.extract(bit_idx, bit_idx);

        opt.assert_soft(&guards.soft_0.implies(&ext._eq(&const_bit_0)), 1u64, None);
        opt.assert_soft(&guards.soft_1.implies(&ext._eq(&const_bit_1)), 1u64, None);
        opt.assert_and_track(&guards.hard_0.implies(&ext._eq(&const_bit_0)), &hard_track_0);
        opt.assert_and_track(&guards.hard_1.implies(&ext._eq(&const_bit_1)), &hard_track_1);

        guards
    }

    pub fn get(&self, soft: bool, set: bool) -> Bool<'ctx> {
        match (soft, set) {
            (true, true) => self.soft_1.clone(),
            (true, false) => self.soft_0.clone(),
            (false, true) => self.hard_1.clone(),
            (false, false) => self.hard_0.clone(),
        }
    }
    pub fn for_value(&self, soft: bool, value: &BV<'ctx>) -> Bool<'ctx> {
        let val_sort = value.get_sort();
        let bv_size = val_sort.bv_size().unwrap();
        assert!(value.kind() == AstKind::Numeral && bv_size == 1, "Invalid 1-bit numeral BV: {:?}", value);
        match value.as_i64() {
            Some(0i64) => self.get(soft, false),
            Some(1i64) => self.get(soft, true),
            Some(other) => panic!(
                "Somehow the value of the 1-bit BV numeral {:?} returned {:?}???? Should be 0 or 1 only?", value, other
            ),
            None => panic!(
                "Somehow the value of the 1-bit BV numeral {:?} could not be extracted.", value
            )
        }
    }

    pub fn soft_eq(&self, value: &BV<'ctx>) -> Bool<'ctx> {
        self.for_value(true, &value.simplify())
    }
    pub fn soft_neq(&self, value: &BV<'ctx>) -> Bool<'ctx> {
        self.for_value(true, &value.bvnot().simplify())
    }
    pub fn hard_eq(&self, value: &BV<'ctx>) -> Bool<'ctx> {
        self.for_value(false, &value.simplify())
    }
    pub fn hard_neq(&self, value: &BV<'ctx>) -> Bool<'ctx> {
        self.for_value(false, &value.bvnot().simplify())
    }
}