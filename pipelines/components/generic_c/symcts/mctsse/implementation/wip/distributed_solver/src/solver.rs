use std::ops::{Deref};

pub enum BinopBV {
    Add, Sub, Mul, Div, SDiv, Mod,
    And, Or, Xor,
}
pub enum UnopBV {
    Neg, Not,
}
pub enum BVExprKind {
    Constant { value: usize },
    Variable { name: String },
    UnaryOperation { op: UnopBV, arg: Box<BVExpr> },
    BinaryOperation { op: BinopBV, left: Box<BVExpr>, right: Box<BVExpr>},
}
pub struct BVExpr {
    pub kind: BVExprKind,
    pub bits: usize,
}
macro_rules! BVBinop {
    ($func:ident, $bvop:ident) => {
        pub fn $func(self, rhs: BVExpr) -> BVExpr {
            assert_eq!(self.bits, rhs.bits);
            let bits = self.bits;
            BVExpr {
                kind: BVExprKind::BinaryOperation {
                    op: BinopBV::$bvop,
                    left: Box::new(self),
                    right: Box::new(rhs)
                },
                bits
            }
        }
    };
}
impl BVExpr {
    // trace_macros!(true);
    // trace_macros!(false);
    BVBinop!(bv_add, Add);
    BVBinop!(bv_sub, Sub);
    BVBinop!(bv_mul, Mul);
    BVBinop!(bv_div, Div);
    BVBinop!(bv_sdiv, SDiv);
    BVBinop!(bv_rem, Mod);
    BVBinop!(bv_and, And);
    BVBinop!(bv_or, Or);
    BVBinop!(bv_xor, Xor);
}

pub enum BVComparison {
    CmpLT, CmpLE, CmpGT, CmpGE,
    CmpSLT, CmpSLE, CmpSGT, CmpSGE,
    CmpEq, CmpNe,
}
pub enum UnopBool {
    Not,
}
pub enum BoolExprKind {
    Constant { value: bool },
    Variable { name: String },
    UnaryOperation { op: UnopBool, arg: Box<BoolExpr>},
    BitvectorCompare { op: BVComparison, left: Box<BVExpr>, right: Box<BVExpr> },
}
pub struct BoolExpr {
    pub kind: BoolExprKind,
}


pub trait Expr {
    fn bits(&self) -> usize;
    fn typecheck(&self) -> bool;
    fn children(&self) -> Vec<&dyn Expr>;
}
impl Expr for BVExpr {
    fn bits(&self) -> usize { self.bits }
    fn typecheck(&self) -> bool
    {
        match &self.kind 
        {
            BVExprKind::Constant {..} => true,
            BVExprKind::Variable {..} => true,
            BVExprKind::UnaryOperation {arg,..} => self.bits == arg.bits && arg.typecheck(),
            BVExprKind::BinaryOperation {left,right,..} => self.bits == left.bits && self.bits == right.bits && left.typecheck() && right.typecheck(),
        }
    }
    fn children(&self) -> Vec<&dyn Expr>
    {
        match &self.kind {
            BVExprKind::Constant {..} => vec!(),
            BVExprKind::Variable {..} => vec!(),
            BVExprKind::UnaryOperation {arg,..} => vec!(arg.deref()),
            BVExprKind::BinaryOperation {left,right,..} => vec!(left.deref(),right.deref()),
        }
    }
}

impl Expr for BoolExpr {
    fn bits(&self) -> usize { 1 }
    fn typecheck(&self) -> bool {
        match &self.kind {
            BoolExprKind::Constant {..} => true,
            BoolExprKind::Variable {..}=> true,
            BoolExprKind::UnaryOperation {arg,..} => arg.typecheck(),
            BoolExprKind::BitvectorCompare {left, right,..} => (left.typecheck() && right.typecheck()),
        }
    }
    fn children(&self) -> Vec<&dyn Expr> {
        match &self.kind {
            BoolExprKind::Constant {..} => vec!(),
            BoolExprKind::Variable {..}=> vec!(),
            BoolExprKind::UnaryOperation {arg,..} => vec!(arg.deref()),
            BoolExprKind::BitvectorCompare {left, right,..} => vec!(left.deref(), right.deref())
        }
    }
}