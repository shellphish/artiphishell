
mod node_reference;
mod node_list;

mod csg_bool;
use csg_bool::BoolNode;

mod csg_bvv;
use csg_bvv::BvvNode;


#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum CsgSort {
    Bool,
    Bvv,
    // Array
}

pub trait CsgNode : std::hash::Hash {
    // fn typecheck(&self) -> bool;
    fn sort(&self) -> CsgSort;
    fn commutative_node_hash(&self) -> u64;
}

pub struct ConstraintGraph {
    pub bool_nodes: Vec<BoolNode>,
    pub bvv_nodes : Vec<BvvNode>,
    // pub array_nodes: Vec<csg_array::ArrayNode>,
}
