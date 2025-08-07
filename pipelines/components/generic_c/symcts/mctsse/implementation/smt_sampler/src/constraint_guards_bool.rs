use z3::{AstKind, Context, Optimize};
use z3::ast::{Bool, Ast};

use crate::{GUARD_PREFIX, Guard};

pub struct BoolConstraintGuards<'ctx> {
    ctx: &'ctx Context,
    soft_false: Guard<'ctx>,
    soft_true: Guard<'ctx>,
    hard_false: Guard<'ctx>,
    hard_true: Guard<'ctx>,
}
impl<'ctx> Clone for BoolConstraintGuards<'ctx> {
    fn clone(&self) -> Self {
        BoolConstraintGuards {
            ctx: self.ctx,
            soft_false: self.soft_false.clone(),
            soft_true: self.soft_true.clone(),
            hard_false: self.hard_false.clone(),
            hard_true: self.hard_true.clone()
        }
    }
}
impl <'ctx> BoolConstraintGuards<'ctx> {
    pub fn create_bool_constraints(ctx: &'ctx Context, opt: &Optimize<'ctx>, var: &Bool<'ctx>) -> BoolConstraintGuards<'ctx> {
        assert!(var.kind() == AstKind::App && var.is_const()); // constant values would be AstKind::Numeral instead, so this is only variables
        let var_name = var.decl().name();

        let soft_one = Bool::new_const(ctx,format!("{GUARD_PREFIX}soft_Bool__{var_name}__is_true"));
        let hard_one = Bool::new_const(ctx,format!("{GUARD_PREFIX}hard_Bool__{var_name}__is_true"));
        let hard_track_0 = Bool::new_const(ctx,format!("{GUARD_PREFIX}track_hard_Bool__{var_name}__is_false"));
        let hard_track_1 = Bool::new_const(ctx,format!("{GUARD_PREFIX}track_hard_Bool__{var_name}__is_true"));
        let guards = BoolConstraintGuards {
            ctx,
            soft_false: soft_one.not(),
            soft_true: soft_one,
            hard_false: hard_one.not(),
            hard_true: hard_one
        };

        opt.assert_soft(&guards.soft_false.implies(&var.not()), 1u64, None);
        opt.assert_soft(&guards.soft_true.implies(&var), 1u64, None);
        opt.assert_and_track(&guards.hard_false.implies(&var.not()), &hard_track_0);
        opt.assert_and_track(&guards.hard_true.implies(&var), &hard_track_1);

        guards
    }

    pub fn get(&self, soft: bool, set: bool) -> Bool<'ctx> {
        match (soft, set) {
            (true, true) => self.soft_true.clone(),
            (true, false) => self.soft_false.clone(),
            (false, true) => self.hard_true.clone(),
            (false, false) => self.hard_false.clone(),
        }
    }
    pub fn for_value(&self, soft: bool, value: &Bool<'ctx>) -> Bool<'ctx> {
        assert!(value.kind() == AstKind::Numeral, "Invalid Bool numeral: {:?}", value);
        match value.as_bool() {
            Some(false) => self.get(soft, false),
            Some(true) => self.get(soft, true),
            None => panic!(
                "Somehow the value of the Bool numeral {:?} could not be extracted.", value
            )
        }
    }

    pub fn soft_eq(&self, value: &Bool<'ctx>) -> Bool<'ctx> {
        self.for_value(true, &value.simplify())
    }
    pub fn soft_neq(&self, value: &Bool<'ctx>) -> Bool<'ctx> {
        self.for_value(true, &value.not().simplify())
    }
    pub fn hard_eq(&self, value: &Bool<'ctx>) -> Bool<'ctx> {
        self.for_value(false, &value.simplify())
    }
    pub fn hard_neq(&self, value: &Bool<'ctx>) -> Bool<'ctx> {
        self.for_value(false, &value.not().simplify())
    }
}