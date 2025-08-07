use crate::csg::{CsgNode, CsgSort, ConstraintGraph};
use std::marker::PhantomData;
use std::hash::Hash;
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct NodeHandle(usize);

impl From<NodeHandle> for usize {
    fn from(handle: NodeHandle) -> usize {
        handle.0
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct CsgNodeReference<T: CsgNode+Hash, U: Hash> {
    pub sort: CsgSort,
    pub handle: NodeHandle,
    pub referenced_node_hash: u64,
    pub extra: U,
    phantom: PhantomData<T>
}

impl<T: CsgNode+Hash, U: Hash> CsgNodeReference<T, U> {
    pub fn new(sort: CsgSort, index: usize, hash: u64, extra: U) -> CsgNodeReference<T, U> {
        CsgNodeReference {
            sort,
            handle: NodeHandle(index),
            referenced_node_hash: hash,
            extra,
            phantom: PhantomData,
        }
    }
}
pub trait CsgReference<'csg, T: CsgNode> {
    fn lookup_node(&self, csg: &'csg ConstraintGraph) -> &'csg T;
}