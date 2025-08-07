#![feature(trait_alias)]
#![feature(associated_type_bounds)]
#![feature(specialization)]
#![feature(associated_type_defaults)]

use smt2;
use std::process;
use num_traits::Num;

mod bitsized;
use bitsized::Bitsized;

pub enum OpUnary {
    Not, Neg, Clear, Set
}
pub enum OpBinary {
    Add, Sub, Mul, Div, SDiv, Rem, SRem,
    And, Or, Xor,
    LShR, AShR, ShL 
}

struct BVV<T: Bitsized+Num> {
    value: T
}
impl<T: Bitsized+Num> BVV<T> { fn new(value: T) -> BVV<T> { BVV { value } }}
impl<T: Bitsized+Num> Bitsized for BVV<T> { fn bits(&self) -> usize { self.value.bits() } }
impl<T: Bitsized+Num> Expr for BVV<T> { fn args(&self) -> Vec<&dyn Expr> { vec!() } }

struct BVS {
    name: String,
    nbits: usize
}
impl BVS { fn new(name: &str, nbits: usize) -> BVS { BVS { name: String::from(name), nbits: nbits } }}
impl Bitsized for BVS { fn bits(&self) -> usize { self.nbits } }
impl Expr for BVS { fn args(&self) -> Vec<&dyn Expr> { vec!() } }

struct UnaryOp<T: Expr> {
    op: OpUnary,
    arg: T
}
impl<T: Expr+Bitsized> Bitsized for UnaryOp<T> { fn bits(&self) -> usize { self.arg.bits() }}
impl<T: Expr> UnaryOp<T> { fn new(op: OpUnary, arg: T) -> UnaryOp<T> { UnaryOp { op, arg } }}
impl<T: Expr> Expr for UnaryOp<T> { fn args(&self) -> Vec<& dyn Expr> { vec!(&self.arg) } }

struct BinaryOp<U: Expr, V: Expr> {
    op: OpBinary,
    left: U,
    right: V,
}
impl<T: Expr+Bitsized, U: Expr+Bitsized> Bitsized for BinaryOp<T, U> 
{
    fn bits(&self) -> usize {
        assert_eq!(self.left.bits(), self.right.bits());
        self.left.bits()
    }
}
impl<T: Expr, U: Expr> BinaryOp<T, U> { fn new(op: OpBinary, left: T, right: U) -> BinaryOp<T, U> { BinaryOp { op, left, right } } }
impl<T: Expr, U: Expr> Expr for BinaryOp<T, U> { fn args(&self) -> Vec<&dyn Expr> { vec!(&self.left, &self.right) } }

pub enum BVExpr<U:Expr+Bitsized,T:Expr+Bitsized> {
    Constant(Box<BVV>),
    Variable(Box<BVS>),
    Unary(Box<UnaryOp>),
    Binary(Box<BinaryOp>),
}
impl<L:Expr+Bitsized, R:Expr+Bitsized> std::ops::Add<R> for BVExpr
{
    type Output = BVExpr<Self,R>;
    fn add(self: L, other: R) -> Self::Output {
        return BVExpr::Binary(BinaryOp::new(OpBinary::Add, self, other))
    }
}

// Don't know if we'll need this

// struct DynamicExpr {
//     reference : Box<dyn Expr>
// }
// impl DynamicExpr { fn new(reference: Box<dyn Expr>) -> DynamicExpr { DynamicExpr { reference } } }
// impl Expr for DynamicExpr { fn args(&self) -> Vec<&dyn Expr> { return self.reference.as_ref().args() } }
// impl std::ops::Deref for DynamicExpr {
//     type Target = dyn Expr;
//     fn deref(&self) -> &Self::Target {
//         return self.reference.as_ref()
//     }
// }
trait Expr {
    fn args(&self) -> Vec<&dyn Expr>;
}

trait BVExpr = Expr + Bitsized;
trait BoolExpr = Expr;


fn b() {
    let x = UnaryOp::new(OpUnary::Neg, BVS::new("asdf", 64));
    let y = BVV::new(0u64);
    let z = BinaryOp::new(OpBinary::Add, x, y);
}

// pub enum ExprBV<ST: BitsizeNum + Sized>
// {
//     Value { value: ST },
//     VariableByte { name: String },
//     UnOp { op: BV_Unop, arg: Box<ExprBV<ST>>},
//     BinOp { op: BV_BinOp, left: Box<ExprBV<ST>>, right: Box<ExprBV<ST>> },
//     IfThenElse { cond: Box<ExprBool>, left: Box<ExprBV<ST>>, right: Box<ExprBV<ST>>},
//     Extract<T2: BitsizeNum + Sized> { inner: Box<ExprBV<T2>> }
// }

// pub enum ExprBool {
//     Value { value: bool },
//     Variable { name: String}
// }

    // struct ExprNode {
    //     op: Operation,
    //     typ: Type,
    //     args: Vec<Expr>
    // }
    // enum Expr {
    //     Variable { name: String, }
    //     Composite(ExprNode),
    //     IntLiteral(i128),
    //     StringLiteral(String),
    //     Identifier(String),
    // }
    
    // trait BitvectorOps
    // {
    //     fn bvadd(left: dyn BitvectorOps, right: dyn BitvectorOps) -> T;
    //     fn bvsub(left: dyn BitvectorOps, right: dyn BitvectorOps) -> T;
    // }
    // pub struct bvadd {
    //     left: Bitvector,
    //     right: Bitvector,
    // }
    // enum Type {
    //     BV,
    //     Bool,
    //     Array,
    // }
    // enum Operation {
    //     // Arithmetic
    //     Add, Sub, Mul, Div, Rem, SDiv,
    //     // Bitwise
    //     And, Or, Not, Neg, Xor,
    //     // Compare
    //     LT, SLT, LE, SLE, GT, SGT, GE, SGE, 
    
    // }
    
    // trait SortedOperation {
    //     fn specialize_for(&self, t: Type) -> String;
    // }
    
    // struct Expression {
    //     result_type: Type,
    //     operation : Operation,
    
    // }
    // enum BV_Expr {
    //     BVS {name: String, bits: u8},
    //     BVV {value: u128, bits: u8},
    //     Add {args: Vec<BV_Expr>},
    
    // }
    // fn main() {
    //     let bool_sort = smt2::GroundSort{
    //         sort: true,
    //         parameters: Vec::new()
    //     };
    //     let solver = process::Command::new("z3")
    //         .args(["-t", "300"]);
    
    //     let c_true = 
    //     let y = smt2::client::Client::new(bool_sort, solver, sm);
    // }
// }
// struct ExprNode {
//     op: Operation,
//     typ: Type,
//     args: Vec<Expr>
// }
// enum Expr {
//     Variable { name: String, }
//     Composite(ExprNode),
//     IntLiteral(i128),
//     StringLiteral(String),
//     Identifier(String),
// }

// trait BitvectorOps
// {
//     fn bvadd(left: dyn BitvectorOps, right: dyn BitvectorOps) -> T;
//     fn bvsub(left: dyn BitvectorOps, right: dyn BitvectorOps) -> T;
// }
// pub struct bvadd {
//     left: Bitvector,
//     right: Bitvector,
// }
// enum Type {
//     BV,
//     Bool,
//     Array,
// }
// enum Operation {
//     // Arithmetic
//     Add, Sub, Mul, Div, Rem, SDiv,
//     // Bitwise
//     And, Or, Not, Neg, Xor,
//     // Compare
//     LT, SLT, LE, SLE, GT, SGT, GE, SGE, 

// }

// trait SortedOperation {
//     fn specialize_for(&self, t: Type) -> String;
// }

// struct Expression {
//     result_type: Type,
//     operation : Operation,
// struct ExprNode {
//     op: Operation,
//     typ: Type,
//     args: Vec<Expr>
// }
// enum Expr {
//     Variable { name: String, }
//     Composite(ExprNode),
//     IntLiteral(i128),
//     StringLiteral(String),
//     Identifier(String),
// }

// trait BitvectorOps
// {
//     fn bvadd(left: dyn BitvectorOps, right: dyn BitvectorOps) -> T;
//     fn bvsub(left: dyn BitvectorOps, right: dyn BitvectorOps) -> T;
// }
// pub struct bvadd {
//     left: Bitvector,
//     right: Bitvector,
// }
// enum Type {
//     BV,
//     Bool,
//     Array,
// }
// enum Operation {
//     // Arithmetic
//     Add, Sub, Mul, Div, Rem, SDiv,
//     // Bitwise
//     And, Or, Not, Neg, Xor,
//     // Compare
//     LT, SLT, LE, SLE, GT, SGT, GE, SGE, 

// }

// trait SortedOperation {
//     fn specialize_for(&self, t: Type) -> String;
// }

// struct Expression {
//     result_type: Type,
//     operation : Operation,

// }
// enum BV_Expr {
//     BVS {name: String, bits: u8},
//     BVV {value: u128, bits: u8},
//     Add {args: Vec<BV_Expr>},

// }
// fn main() {
//     let bool_sort = smt2::GroundSort{
//         sort: true,
//         parameters: Vec::new()
//     };
//     let solver = process::Command::new("z3")
//         .args(["-t", "300"]);

//     let c_true = 
//     let y = smt2::client::Client::new(bool_sort, solver, sm);
// }

// }
// enum BV_Expr {
//     BVS {name: String, bits: u8},
//     BVV {value: u128, bits: u8},
//     Add {args: Vec<BV_Expr>},

// }
// fn main() {
//     let bool_sort = smt2::GroundSort{
//         sort: true,
//         parameters: Vec::new()
//     };
//     let solver = process::Command::new("z3")
//         .args(["-t", "300"]);

//     let c_true = 
//     let y = smt2::client::Client::new(bool_sort, solver, sm);
// }