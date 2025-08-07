use std::{fmt::{Debug, Display}, collections::{HashSet, HashMap}};
use z3::ast::{Ast, Bool, BV};
use z3::{FuncDecl, Context};

use crate::z3_util::ast_visitor::consts;

#[derive(Eq, PartialEq, PartialOrd, Ord, Debug, Clone)]
pub struct SymCCInputVars<'ctx> {
    pub byte_vars: Vec<BV<'ctx>>,
    full_ast: BV<'ctx>,
}

pub fn symcc_name_to_byte_idx(name: &str) -> usize {
    assert!(name.starts_with("k!"));
    // println!("Parsing variable: {}", name);
    let n = usize::from_str_radix(&name[2..], 10).expect(&format!("Invalid index of SymCC variable? {:?}", name));
    assert!(n % 10 == 0);
    n / 10
}
pub fn symcc_var_for_idx<'ctx>(ctx: &'ctx Context, idx: usize) -> BV<'ctx> {
    BV::new_const(ctx, format!("k!{:02}", idx * 10), 8)
}
impl<'ctx> SymCCInputVars<'ctx> {
    pub fn from_vars(ctx: &'ctx Context, vars: Vec<BV<'ctx>>) -> SymCCInputVars<'ctx> {
        let max_byte_index = vars.iter().map(|x| symcc_name_to_byte_idx(&x.decl().name())).max().unwrap();
        let mut byte_idx_to_var: HashMap<usize, BV<'ctx>> = vars.into_iter().map(|x| (symcc_name_to_byte_idx(&x.decl().name()), x)).collect();

        let byte_vars = (0..(max_byte_index+1)).map(|i| {
            byte_idx_to_var.entry(i).or_insert_with(|| symcc_var_for_idx(ctx, i)).clone()
        }).collect::<Vec<_>>();

        log::debug!(target: "quick_sample", "byte_vars: {:?}", byte_vars);
        assert!(byte_vars
            .iter()
            .enumerate()
            .all(
                |(i, x)| {
                    let symcc_idx = symcc_name_to_byte_idx(&x.decl().name());
                    assert!(x.decl().range().bv_size() == Some(8), "{:?} is not an 8-bit BV!", x);
                    assert!(symcc_idx == i, "symcc_idx={:?} does not match the expected index of {:?} for {:?}", symcc_idx, i, x);
                    true
                })
            );

        let full_ast = byte_vars.iter().fold(
            None,
            |x: Option<BV<'ctx>>, y| Some(x.map_or(y.clone(), |old| old.concat(y)))
        );
        let full_ast = match full_ast {
            Some(x) => x,
            None => panic!("We cannot have a non-existent full_ast?? full_ast={:?}", &full_ast),
        };
        SymCCInputVars {
            byte_vars,
            full_ast,
        }
    }
    pub fn from_constraints(ctx: &'ctx Context, csts: Vec<Bool<'ctx>>) -> SymCCInputVars<'ctx> {
        let mut vars: HashSet<BV<'ctx>> = Default::default();
        for cst in csts {
            vars.extend(consts(&cst.into()).into_iter().map(|x|x.as_bv().unwrap()));
        }

        Self::from_vars(ctx, vars.into_iter().collect())
    }
    pub fn index(&self, decl: FuncDecl<'ctx>) -> usize {
        assert!(decl.range().bv_size() == Some(8));
        let idx = symcc_name_to_byte_idx(&decl.name());
        assert!(idx < self.byte_vars.len());
        assert!(self.byte_vars[idx].decl() == decl);
        idx
    }
    pub fn byte(&self, byte_idx: usize) -> &BV<'ctx> {
        &self.byte_vars[byte_idx]
    }
    pub fn full_ast(&self) -> &BV<'ctx> {
        &self.full_ast
    }
    pub fn iter(&self) -> std::slice::Iter<BV<'ctx>> {
        self.byte_vars.iter()
    }
    pub fn num_vars(&self) -> usize {
        self.byte_vars.len()
    }
}

impl<'ctx> Display for SymCCInputVars<'ctx> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <Self as Debug>::fmt(self, f)
    }
}