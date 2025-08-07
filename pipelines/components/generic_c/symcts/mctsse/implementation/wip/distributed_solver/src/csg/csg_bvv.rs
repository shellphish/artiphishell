use crate::csg::{CsgNode,CsgSort,ConstraintGraph};
use crate::csg::node_reference::{CsgNodeReference,CsgReference};
use std::sync::{Arc,Weak};
use std::hash::{Hash,Hasher};
use std::collections::hash_map::DefaultHasher;

#[derive(Debug,Hash,Copy,Clone,PartialEq,Eq)]
pub enum UnaryBvvOp {
    Not, Neg
}
#[derive(Debug,Hash,Copy,Clone,PartialEq,Eq)]
pub enum BinaryBvvOp {
    Add, Sub, Mul, Div, SDiv, Mod, SMod,
    And, Or, Xor, 
}
impl BinaryBvvOp {
    fn is_commutative(&self) -> bool {
        match self {
            BinaryBvvOp::Add | BinaryBvvOp::Mul | BinaryBvvOp::And | BinaryBvvOp::Or | BinaryBvvOp::Xor => true,
            _ => false
        }
    }
}
#[derive(Debug,Hash,Copy,Clone,PartialEq,Eq)]
pub struct BvvRefExtra {
    bits: usize,
}
type BvvRef = CsgNodeReference<BvvNode, BvvRefExtra>;

impl<'csg> CsgReference<'csg, BvvNode> for BvvRef {
    fn lookup_node(&self, csg: &'csg ConstraintGraph) -> &'csg BvvNode {
        assert_eq!(self.sort, CsgSort::Bvv);
        let r = &csg.bvv_nodes[usize::from(self.handle)];
        assert_eq!(r.sort(), CsgSort::Bvv);
        r
    }
}

#[derive(Debug,Hash,Clone,PartialEq,Eq)]
pub enum BvvNodeKind {
    Constant { value: bitvec::vec::BitVec },
    Variable { name: String },
    UnaryOp  { op: UnaryBvvOp, arg: BvvRef },
    BinaryOp { op: BinaryBvvOp, left: BvvRef, right: BvvRef },
}

#[derive(Debug,Hash,Clone,PartialEq,Eq)]
pub struct BvvNode {
    pub kind: BvvNodeKind,
    pub bits: usize,
    pub node_hash: u64,
}

fn compute_hash<T: Hash>(o: &T) -> u64 {
    let hasher : DefaultHasher = DefaultHasher::default();
    o.hash(&mut hasher);
    hasher.finish()
}
impl CsgNode for BvvNode {
    fn sort(&self) -> CsgSort {
        CsgSort::Bvv
    }

    fn commutative_node_hash(&self) -> u64 {
        let hasher : DefaultHasher = DefaultHasher::default();
        self.bits.hash(&mut hasher);
        match &self.kind {
            BvvNodeKind::Constant { value } => value.hash(&mut hasher),
            BvvNodeKind::Variable { name } => name.hash(&mut hasher),
            BvvNodeKind::UnaryOp { op, arg } => {
                op.hash(&mut hasher);
                arg.hash(&mut hasher);
            }
            BvvNodeKind::BinaryOp {op, left, right} => {
                op.hash(&mut hasher);
                let h1 = compute_hash(left);
                let h2 = compute_hash(right);
                let min = if h1 < h2 {h1} else {h2};
                let max = if h1 < h2 {h2} else {h1};
                min.hash(&mut hasher);
                max.hash(&mut hasher);
            }
        }
        hasher.finish()
    }
}

impl BvvNode {
    fn new(kind: BvvNodeKind, bits: usize) -> BvvNode {
        let node = BvvNode { kind, bits, node_hash: 0};
        let hash = node.commutative_node_hash();
        node.node_hash = hash;
        node
    }
}

pub trait BvvOps {
    fn bvv_const(&mut self, v: bitvec::vec::BitVec) -> BvvRef;
    fn bvv_var(&mut self, name: &str, bits: usize) -> BvvRef;
    fn bvv_not(&mut self, arg: BvvRef) -> BvvRef;
    fn bvv_and(&mut self, left: BvvRef, right: BvvRef) -> BvvRef;
    fn bvv_or(&mut self, left: BvvRef, right: BvvRef) -> BvvRef;
    fn bvv_xor(&mut self, left: BvvRef, right: BvvRef) -> BvvRef;
}

impl BvvOps for ConstraintGraph {
    fn bvv_const(&mut self, v: bitvec::vec::BitVec, ) -> BvvRef {
        let bits = v.len();
        let node = BvvNode::new(BvvNodeKind::Constant { value: v }, bits);
        let hash = node.node_hash;
        self.bvv_nodes.push(node);
        BvvRef::new(CsgSort::Bvv, self.bvv_nodes.len(), hash, BvvRefExtra { bits })
    }
    fn bvv_var(&mut self, name: &str, bits: usize) -> BvvRef {
        let node = BvvNode::new(BvvNodeKind::Variable { name: String::from(name) }, bits);
        let hash = node.node_hash;
        self.bvv_nodes.push(node);
        BvvRef::new(CsgSort::Bvv, self.bvv_nodes.len(), hash, BvvRefExtra { bits })
    }
    fn bvv_not(&mut self, arg: BvvRef) -> BvvRef {
        let bits = arg.extra.bits;
        let node = BvvNode::new(BvvNodeKind::UnaryOp { op: UnaryBvvOp::Not, arg }, bits);
        let hash = node.node_hash;
        self.bvv_nodes.push(node);
        BvvRef::new(CsgSort::Bvv, self.bvv_nodes.len(), hash, BvvRefExtra { bits })  // TODO: better way to allocate new node that can be synchronized
    }
    fn bvv_and(&mut self, left: BvvRef, right: BvvRef) -> BvvRef {
        assert_eq!(left.extra.bits, right.extra.bits);
        let bits = left.extra.bits;
        let node = BvvNode::new(BvvNodeKind::BinaryOp { op: BinaryBvvOp::And, left, right }, bits);
        let hash = node.node_hash;
        self.bvv_nodes.push(node);
        BvvRef::new(CsgSort::Bvv, self.bvv_nodes.len(), hash, BvvRefExtra { bits })
    }
    fn bvv_or(&mut self, left: BvvRef, right: BvvRef) -> BvvRef {
        assert_eq!(left.extra.bits, right.extra.bits);
        let bits = left.extra.bits;
        let node = BvvNode::new(BvvNodeKind::BinaryOp { op: BinaryBvvOp::Or, left, right }, bits);
        let hash = node.node_hash;
        self.bvv_nodes.push(node);
        BvvRef::new(CsgSort::Bvv, self.bvv_nodes.len(), hash, BvvRefExtra { bits })
    }
    fn bvv_xor(&mut self, left: BvvRef, right: BvvRef) -> BvvRef {
        assert_eq!(left.extra.bits, right.extra.bits);
        let bits = left.extra.bits;
        let node = BvvNode::new(BvvNodeKind::BinaryOp { op: BinaryBvvOp::Xor, left, right }, bits);
        let hash = node.node_hash;
        self.bvv_nodes.push(node);
        BvvRef::new(CsgSort::Bvv, self.bvv_nodes.len(), hash, BvvRefExtra { bits })
    }
}