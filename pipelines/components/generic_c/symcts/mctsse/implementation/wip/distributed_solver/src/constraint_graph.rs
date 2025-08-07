use crate::append_only_graph::{AppendOnlyGraph, Node};


#[derive(Debug, Hash, Eq, PartialEq)]
pub enum AstBinOp {
    Add, Sub, Mul, Div, SDiv, Rem, SRem,
    And, Or, Xor
}
impl AstBinOp {
    fn is_commutative(&self) -> bool {
        match &self {
            AstBinOp::Add | AstBinOp::Mul => true,
            AstBinOp::Sub | AstBinOp::Div | AstBinOp::SDiv | AstBinOp::Rem | AstBinOp::SRem => false,
            AstBinOp::And | AstBinOp::Or | AstBinOp::Xor => true,
        }
    }
}
#[derive(Debug, Hash, Eq, PartialEq)]
pub enum AstBinPredicate {
    SignedLess, SignedLessOrEqual, SignedGreater, SignedGreaterOrEqual,
    Less, LessOrEqual, Greater, GreaterOrEqual,
    Equal, Unequal,
}
#[derive(Debug, Hash, Eq, PartialEq)]
pub enum AstUnaryPredicate {
    IsZero, IsSigned, IsParity
}
#[derive(Debug, Hash, Eq, PartialEq)]
pub enum AstUnOp {
    Not, Neg
}


#[derive(Hash, Eq, PartialEq)]
pub enum AstKind {
    Constant { value: u128 },
    Variable { name: String },
    UnOp { op: AstUnOp, arg: Node },
    BinOp { op: AstBinOp, left: Node, right: Node },
    Extract { outer: Node, offset: usize, length: usize },
    ZeroExtend { inner: Node, by: usize },
    SignExtend { inner: Node, by: usize },
    If { condition: Node, if_true: Node, if_false: Node },
    UnaryPredicate { op: AstUnaryPredicate, arg: Node},
    BinaryPredicate { op: AstBinPredicate, left: Node, right: Node},
}
impl std::fmt::Debug for AstKind {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        match &self {
            AstKind::Constant {value} => write!(fmt, "Const({})", value),
            AstKind::Variable {name} => write!(fmt, "Var({:?})", name),
            AstKind::UnOp { op, arg } => write!(fmt, "{:?}({:?})", op, arg),
            AstKind::BinOp {op, left, right} => write!(fmt, "{:?}({:?}, {:?})", op, left, right),
            AstKind::Extract { outer, offset, length } => write!(fmt, "{:?}[{}:{})", outer, offset, offset+length),
            AstKind::ZeroExtend { inner, by } => write!(fmt, "ZeroExtend({:?}, {})", inner, by),
            AstKind::SignExtend { inner, by } => write!(fmt, "SignExtend({:?}, {})", inner, by),
            AstKind::If { condition, if_true, if_false } => write!(fmt, "If({:?}, {:?}, {:?})", condition, if_true, if_false),
            AstKind::UnaryPredicate { op, arg } => write!(fmt, "{:?}({:?})", op, arg),
            AstKind::BinaryPredicate { op, left, right } => write!(fmt, "{:?}({:?}, {:?})", op, left, right),
        }
    }
}

#[derive(Hash, Eq, PartialEq)]
pub struct AstNode {
    pub kind: AstKind,
    pub bits: usize,
}
impl std::fmt::Debug for AstNode {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(fmt, "[{}] {:?}", self.bits, self.kind)
    }
}


#[derive(Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct AstEdge {
    pub parameter_position: Option<usize>,
    pub bits: usize,
}
impl std::fmt::Debug for AstEdge {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(fmt, "[param={:?},bits={}]", self.parameter_position, self.bits)
    }
}

macro_rules! ast_binop {
    ($binop_name:ident, $local_name:ident) => {
        pub fn $local_name(&mut self, left: Node, right: Node) -> Node {
            self.ast_binop(AstBinOp::$binop_name, left, right)
        }
    };
}

pub type AstGraph = AppendOnlyGraph<AstNode, AstEdge>;
impl Default for AstGraph {
    fn default() -> Self {
        AstGraph::new(0x1000)
    }
}

impl AstGraph
{
    pub fn ast_var(&mut self, name: String, bits: usize) -> Node {
        self.add_node(AstNode { kind: AstKind::Variable { name }, bits })
    }
    pub fn ast_const_int(&mut self, value: usize, bits: usize) -> Node {
        self.add_node(AstNode { kind: AstKind::Constant { value: value as u128 }, bits })
    }
    pub fn ast_binop(&mut self, op: AstBinOp, left: Node, right: Node) -> Node {
        let left_bits = self.node_data(left).unwrap().bits;
        let right_bits = self.node_data(right).unwrap().bits;
        assert_eq!(left_bits, right_bits);
        let commutes = op.is_commutative();
        let new_node = self.add_node(AstNode {kind: AstKind::BinOp {op, left, right}, bits: left_bits});
        self.add_edge(new_node, left, AstEdge {parameter_position: if !commutes {Some(0)} else {None}, bits: left_bits});
        self.add_edge(new_node, right, AstEdge {parameter_position: if !commutes {Some(1)} else {None}, bits: right_bits});
        new_node
    }
    ast_binop!(Add, ast_add);
    ast_binop!(Sub, ast_sub);
    ast_binop!(Mul, ast_mul);
    ast_binop!(Div, ast_div);
    ast_binop!(SDiv, ast_sdiv);
    ast_binop!(Rem, ast_rem);
    ast_binop!(SRem, ast_srem);
    ast_binop!(And, ast_and);
    ast_binop!(Or, ast_or);
    ast_binop!(Xor, ast_xor);
}


