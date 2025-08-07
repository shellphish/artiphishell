use std::collections::HashMap;

use z3::ast::{Ast, Dynamic};
use z3::FuncDecl;
use petgraph::unionfind::UnionFind;

use super::ast_visitor::consts;

pub fn partition_symcc<'ctx>(vars: Vec<FuncDecl<'ctx>>, csts: Vec<Dynamic<'ctx>>) {
    let mut unioned_vars : UnionFind<usize> = UnionFind::new(vars.len() + csts.len());

    let ncst = csts.len();
    let nvars = vars.len();
    let var_to_idx : HashMap<&FuncDecl<'ctx>, usize> = vars.iter().enumerate().map(|(i, x)| (x, ncst+i)).collect();
    assert!(nvars == var_to_idx.len());

    for (cst_idx, cst) in csts.iter().enumerate() {
        let vars = consts(cst);
        for v in vars {
            let var_idx = *var_to_idx.get(&v.decl()).unwrap();
            unioned_vars.union(cst_idx, var_idx);
        }
    }
    println!("unioned_vars: {:?}", unioned_vars.into_labeling());
}
