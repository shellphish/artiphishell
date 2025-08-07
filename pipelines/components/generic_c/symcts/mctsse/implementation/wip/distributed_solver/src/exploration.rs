use std::sync;
use std::collections::HashMap;

struct Input {
    data: Box<[u8]>,
    branch_counts: HashMap<Branch,u128>,
    path_hash: u64,
}
pub struct Branch(u64, u64);

struct BranchExplorationStats {
    num_inputs_hit: u64,
}

pub type TreeNode = sync::RwLock<TreeNodeData>;
pub struct TreeNodeData {
    pub inputs_per_branch : HashMap<Branch, u128>,
    pub 
}