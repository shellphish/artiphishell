use std::collections::HashSet;

use z3::ast::{Ast, Dynamic};
pub trait DFSIter<'ctx> {
    fn iter_dfs_pre(&self) -> AstIterator_DFS_Preorder<'ctx>;
}

#[derive(Debug)]
#[allow(non_camel_case_types)]
pub struct AstIterator_DFS_Preorder<'ctx> {
    remaining: Vec<Dynamic<'ctx>>,
    seen : HashSet<u32>,
}
impl<'ctx> AstIterator_DFS_Preorder<'ctx> {
    pub fn new(ast: Dynamic<'ctx>) -> AstIterator_DFS_Preorder<'ctx>{
        AstIterator_DFS_Preorder {
            remaining: vec![ast],
            seen: HashSet::new()
        }
    }
}
impl<'ctx> Default for AstIterator_DFS_Preorder<'ctx> {
    fn default() -> Self {
        AstIterator_DFS_Preorder {
            remaining: vec![],
            seen: HashSet::new(),
        }
    }
}
impl<'ctx> Iterator for AstIterator_DFS_Preorder<'ctx> {
    type Item = Dynamic<'ctx>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.remaining.pop() {
                None => { return None },
                Some(ast) => {
                    let id = ast.get_ast_id();
                    if self.seen.contains(&id) {
                        continue;
                    }
                    self.seen.insert(id);
                    let mut children_rev = ast.children();
                    children_rev.reverse();
                    self.remaining.extend(children_rev.into_iter());
                    return Some(ast);
                }
            }
        }

    }
}

impl<'ctx> DFSIter<'ctx> for Dynamic<'ctx> {
    fn iter_dfs_pre(&self) -> AstIterator_DFS_Preorder<'ctx> {
        AstIterator_DFS_Preorder::new(self.clone())
    }
}