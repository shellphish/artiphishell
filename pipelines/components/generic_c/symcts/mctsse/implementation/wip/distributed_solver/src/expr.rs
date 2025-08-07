pub trait SmtlibCompatible {
    fn to_smt2(&self) -> String;
    fn from_smt2(smt2_repr: &str) -> Self;
}

pub enum BV_Expression {
    Add(left: BV_Expression, right: BV_Expression),
    Sub(left: BV_Expression, right: BV_Expression)
}