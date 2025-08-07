use std::collections::hash_map::HashMap;
use std::vec::{Vec};
use multimap::MultiMap;
use std::fmt;

#[derive(Eq, PartialEq, Ord, PartialOrd, Hash, Copy, Clone)]
pub struct Node {
    index: usize
}
impl fmt::Debug for Node {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "Node({})", self.index)
    }
}
impl From<Node> for usize {
    fn from(v: Node) -> usize {
        v.index
    }
}
pub struct AppendOnlyGraph<NodeDataT, EdgeDataT> {
    _nodes: Vec<NodeDataT>,
    _edge_data: HashMap<(Node, Node), EdgeDataT>,
    _successors: MultiMap<Node, Node>,
    _predecessors: MultiMap<Node, Node>,
}

impl<N, E> AppendOnlyGraph<N, E> {
    pub fn new(initial_capacity: usize) -> Self {
        AppendOnlyGraph {
            _nodes: Vec::with_capacity(initial_capacity),
            _successors: MultiMap::new(),
            _predecessors: MultiMap::new(),
            _edge_data: Default::default(),
        }
    }
    pub fn add_node(&mut self, nd: N) -> Node {
        let index = Node { index: self._nodes.len() };
        self._nodes.push(nd);
        index
    }
    pub fn add_edge(&mut self, src: Node, dst: Node, edge_data: E) {
        self._successors.insert(src, dst);
        self._predecessors.insert(dst, src);
        self._edge_data.insert((src,dst), edge_data);
    }
    pub fn successors(&self, node: Node) -> Option<&Vec<Node>> {
        self._successors.get_vec(&node)
    }
    pub fn predecessors(&self, node: Node) -> Option<&Vec<Node>> {
        self._predecessors.get_vec(&node)
    }
    pub fn edge_data(&self, src: Node, dst: Node) -> Option<&E> {
        self._edge_data.get(&(src,dst))
    }
    pub fn node_data(&self, node: Node) -> Option<&N> {
        self._nodes.get(node.index)
    }
}
impl<N: std::fmt::Debug, E: std::fmt::Debug> std::fmt::Debug for AppendOnlyGraph<N,E> {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        writeln!(fmt, "Nodes:")?;
        for (idx, node) in self._nodes.iter().enumerate() {
            writeln!(fmt, "\t{}: {:?}", idx, node)?;
        }
        writeln!(fmt, "Edges:")?;
        for ((src,dst), edge_data) in self._edge_data.iter() {
            writeln!(fmt, "\t{:?}->{:?}: {:?}", src, dst, edge_data)?;
        }
        Ok(())
    }
}


