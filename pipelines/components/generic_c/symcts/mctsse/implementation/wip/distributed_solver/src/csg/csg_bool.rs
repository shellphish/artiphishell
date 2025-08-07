use crate::csg::{CsgNode,CsgSort,ConstraintGraph};
use crate::csg::node_reference::{CsgNodeReference,CsgReference};

use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum BoolUnOp {
    Not
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum BoolBinOp {
    And, Or, Xor,
}

type BoolRef = CsgNodeReference<BoolNode, ()>;

impl<'csg> CsgReference<'csg, BoolNode> for BoolRef {
    fn lookup_node(&self, csg: &'csg ConstraintGraph) -> &'csg BoolNode {
        assert_eq!(self.sort, CsgSort::Bool);
        let r = &csg.bool_nodes[usize::from(self.handle)];
        assert_eq!(r.sort(), CsgSort::Bool);
        assert_eq!(r.commutative_node_hash(), self.referenced_node_hash);
        r
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum BoolNodeKind {
    Constant { value: bool },
    Variable { name: String },
    UnaryOp { op: BoolUnOp, arg: BoolRef},
    BinaryOp{ op: BoolBinOp, left: BoolRef, right: BoolRef}
}
#[derive(Debug,Hash,Clone,PartialEq,Eq)]
pub struct BoolNode {
    kind: BoolNodeKind,
}

fn calc_hash<T: Hash>(v: T) -> u64 {
    let hasher = DefaultHasher::default();
    v.hash(&mut hasher);
    hasher.finish()
}
impl CsgNode for BoolNode {
    fn sort(&self) -> CsgSort {
        CsgSort::Bool
    }
    fn commutative_node_hash(&self) -> u64 {
        let hasher = DefaultHasher::default();
        match &self.kind {
            BoolNodeKind::Constant {value} => self.kind.hash(&mut hasher),
            BoolNodeKind::Variable {name: String} => self.kind.hash(&mut hasher),
            BoolNodeKind::UnaryOp {op, arg } => {
                op.hash(&mut hasher);
                arg.hash(&mut hasher);
            },
            BoolNodeKind::BinaryOp {op, left, right} => {
                op.hash(&mut hasher);
                let h1 = calc_hash(left);
                let h2 = calc_hash(right);
                let min = if h1 < h2 { h1 } else { h2 };
                let max = if h1 < h2 { h2 } else { h1 };
                min.hash(&mut hasher);
                max.hash(&mut hasher);
            }
        }
        hasher.finish()
    }
}

pub trait BoolOps {
    fn bool_const(&mut self, v: bool) -> BoolRef;
    fn bool_var(&mut self, name: &str) -> BoolRef;
    fn bool_not(&mut self, arg: BoolRef) -> BoolRef;
    fn bool_and(&mut self, left: BoolRef, right: BoolRef) -> BoolRef;
    fn bool_or(&mut self, left: BoolRef, right: BoolRef) -> BoolRef;
    fn bool_xor(&mut self, left: BoolRef, right: BoolRef) -> BoolRef;
}

impl BoolOps for ConstraintGraph {
    fn bool_const(&mut self, v: bool) -> BoolRef {
        self.bool_nodes.push(BoolNode {
            kind: BoolNodeKind::Constant { value: v }
        });
        BoolRef::new(CsgSort::Bool, self.bool_nodes.len(), ())
    }
    fn bool_var(&mut self, name: &str) -> BoolRef {
        self.bool_nodes.push(BoolNode {
            kind: BoolNodeKind::Variable { name: String::from(name) }
        });
        BoolRef::new(CsgSort::Bool, self.bool_nodes.len(), ())
    }
    fn bool_not(&mut self, arg: BoolRef) -> BoolRef {
        self.bool_nodes.push(BoolNode {
            kind: BoolNodeKind::UnaryOp {
                op: BoolUnOp::Not,
                arg
            }
        });
        BoolRef::new(CsgSort::Bool, self.bool_nodes.len(), ())  // TODO: better way to allocate new node that can be synchronized
    }
    fn bool_and(&mut self, left: BoolRef, right: BoolRef) -> BoolRef {
        self.bool_nodes.push(BoolNode {
            kind: BoolNodeKind::BinaryOp {
                op: BoolBinOp::And,
                left,
                right
            }
        });
        BoolRef::new(CsgSort::Bool, self.bool_nodes.len(), ())
    }
    fn bool_or(&mut self, left: BoolRef, right: BoolRef) -> BoolRef {
        self.bool_nodes.push(BoolNode {
            kind: BoolNodeKind::BinaryOp {
                op: BoolBinOp::Or,
                left,
                right
            }
        });
        BoolRef::new(CsgSort::Bool, self.bool_nodes.len(), ())
    }
    fn bool_xor(&mut self, left: BoolRef, right: BoolRef) -> BoolRef {
        self.bool_nodes.push(BoolNode {
            kind: BoolNodeKind::BinaryOp {
                op: BoolBinOp::Xor,
                left,
                right
            }
        });
        BoolRef::new(CsgSort::Bool, self.bool_nodes.len(), ())
    }
}