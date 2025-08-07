use z3::ast::Bool;

pub mod symcc;
pub mod generic;
mod constraint_guards_bit;
mod constraint_guards_bool;
mod z3_util;

pub use constraint_guards_bit::BitConstraintGuards;
pub use constraint_guards_bool::BoolConstraintGuards;

pub const GUARD_PREFIX: &str = "__guard__";
type Guard<'ctx> = Bool<'ctx>;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
