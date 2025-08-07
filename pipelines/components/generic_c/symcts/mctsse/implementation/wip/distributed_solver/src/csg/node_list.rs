use crate::csg::CsgNode;

pub struct NodeList<T: CsgNode> {
    nodes: Vec<T>,
    next_node: usize,
}