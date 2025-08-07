use std::collections::{HashMap, HashSet};
use std::fmt::{Display, Debug};
use std::hash::Hash;

use itertools::Itertools;
use z3::{Model, SortKind, FuncDecl, Context};
use z3::ast::{Dynamic, Ast, BV, Bool};

use crate::GUARD_PREFIX;

use super::model_mutation::ModelMutation;

#[derive(Eq, PartialEq, Clone)]
pub struct SimpleModel<'ctx> {
    pub ctx: &'ctx Context,
    pub bvs: HashMap<FuncDecl<'ctx>, u64>,
    pub bools: HashMap<FuncDecl<'ctx>, bool>,
    pub asts: HashMap<FuncDecl<'ctx>, Dynamic<'ctx>>,
}

impl<'ctx> Hash for SimpleModel<'ctx> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        state.write(&format!("{:?}", self).as_bytes());
    }
}
impl<'ctx> PartialOrd for SimpleModel<'ctx> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        let repr1 = format!("{:?}", self);
        let repr2 = format!("{:?}", other);
        Some(repr1.cmp(&repr2))
    }
}
impl<'ctx> Ord for SimpleModel<'ctx> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.partial_cmp(other).unwrap()
    }
}

impl<'ctx> Display for SimpleModel<'ctx> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <SimpleModel as std::fmt::Debug>::fmt(self, f)
    }
}

impl<'ctx> Debug for SimpleModel<'ctx> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let asts = self.asts
            .iter()
            .sorted_by( |x, y| {
                (x.0.as_dynamic(), x.1).cmp(&(y.0.as_dynamic(), y.1))
            })
            .map(
                |(decl, val)| (
                    format!("{} {:?}", decl.name(), decl.range()),
                    format!("{:?}", val)
                )
            );
        f.debug_map().entries(asts).finish()
    }
}


impl<'ctx> SimpleModel<'ctx> {
    pub fn new(ctx: &'ctx Context) -> SimpleModel<'ctx> {
        SimpleModel {
            ctx,
            bvs: Default::default(),
            bools: Default::default(),
            asts: Default::default()
        }
    }
    pub fn from_model(model: &Model<'ctx>) -> SimpleModel<'ctx> {
        let ctx = model.get_context();
        let mut bvs = HashMap::new();
        let mut bools = HashMap::new();
        let mut asts = HashMap::new();
        // println!("original model: {:?}", model);
        for decl in model.constants() {
            assert!(decl.arity() == 0); // an application with no arguments is a const usually
            if decl.name().starts_with(GUARD_PREFIX) {
                continue;
            }
            let interp = model.get_const_interpretation(&decl);
            // println!("Interpretation of {:?} is {:?}", decl, interp);
            let kind = decl.range().kind();
            let new_decl = decl.clone();
            match kind {
                SortKind::BV => {
                    let bv_size = decl.range().bv_size().expect(&format!("bvs have to have sizes, why doesn't {:?}", &decl));
                    assert!(bv_size <= 64, "");
                    if let Some(v) = interp {
                        asts.insert(new_decl, v.clone());
                        let val = v.as_bv().unwrap().as_u64().expect(
                            &format!("model interpretation of bv {:?} could not be converted to a value using as_u64 on {:?}", &decl, &v)
                            );
                        bvs.insert(decl, val);
                    }
                    else {
                        let val = rand::random();
                        bvs.insert(new_decl, val);
                        asts.insert(decl, BV::from_u64(ctx, val, bv_size.try_into().unwrap()).into());
                    }
                },
                SortKind::Bool => {
                    let (ast, val) = if let Some(bool_ast) = interp {
                        let msg = format!(
                            "model interpretation of bool {:?} could not be converted to a value using as_bool on {:?}",
                            &decl,
                            &bool_ast
                        );
                        (bool_ast.clone(), bool_ast.as_bool().unwrap().as_bool().expect(&msg))
                    }
                    else {
                        let val = rand::random();
                        (Bool::from_bool(ctx, val).into(), val)
                    };
                    bools.insert(new_decl, val);
                    asts.insert(decl, ast);
                }
                _ => unimplemented!()
            }
        }

        let res = SimpleModel {
            ctx,
            bvs,
            bools,
            asts
        };
        // println!("converted model: {:?}", res);
        res
    }

    pub fn evaluate(&self, csts: &[&Dynamic<'ctx>]) -> Vec<Dynamic<'ctx>> {
        let replacements: Vec<(Dynamic<'ctx>, Dynamic<'ctx>)> = self.asts.iter()
            .map(|(decl, ast)| (decl.apply(&[]), ast.clone()))
            .collect();
        let repl = replacements.iter().map(|(a,b)| (a,b)).collect::<Vec<_>>();
        csts.iter()
            .map(|c| c.substitute(&repl[..]).simplify())
            .collect()
    }
    pub fn satisfies_constraints(&self, csts: &[&Bool<'ctx>]) -> bool {
        let replacements: Vec<(Dynamic<'ctx>, Dynamic<'ctx>)> = self.asts.iter()
            .map(|(decl, ast)| (decl.apply(&[]), ast.clone()))
            .collect();
        let repl = replacements.iter().map(|(a,b)| (a,b)).collect::<Vec<_>>();
        csts.iter()
            .map(|c| c.substitute(&repl[..]).simplify())
            .all(|x| x.as_bool().expect("after substitution all constraints should be true"))
    }

    pub fn variables(&self) -> HashSet<FuncDecl<'ctx>> {
        self.bvs.keys().chain(self.bools.keys()).map(FuncDecl::clone).collect()
    }

    pub fn get_bv_val(&self, decl: &FuncDecl<'ctx>) -> u64 {
        assert!(decl.arity() == 0 && decl.range().kind() == SortKind::BV);
        self.bvs.get(decl)
            .map(|&v| v)
            .expect(&format!("All bvs should already be defined in the model?? {:?} is missing in {:?}", decl, self))
    }

    pub fn get_bit_val(&self, decl: &FuncDecl<'ctx>, bit_idx: u32) -> bool {
        let bvval = self.get_bv_val(decl);
        let bitval = (bvval >> bit_idx) & 1;
        assert!(bitval == 0 || bitval == 1);
        bitval != 0
    }

    pub fn get_bool_val(&self, decl: &FuncDecl<'ctx>) -> bool {
        assert!(decl.arity() == 0 && decl.range().kind() == SortKind::Bool);
        self.bools.get(decl)
            .map(|&v| v)
            .expect(&format!("All bools should already be defined in the model?? {:?} is missing in {:?}", decl, self))
    }

    pub fn minimal_mutation(&self, other: &SimpleModel<'ctx>) -> ModelMutation<'ctx> {
        let bv_vars_self = self.bvs.keys().collect::<HashSet<_>>();
        let bv_vars_others = other.bvs.keys().collect::<HashSet<_>>();
        assert!(bv_vars_self == bv_vars_others, "bv variables are different between {:?} and {:?}", bv_vars_self, bv_vars_others);
        assert!(self.bools.keys().collect::<HashSet<_>>() == other.bools.keys().collect::<HashSet<_>>(), "bool variables are different between {:?} and {:?}", self, other);
        let mut bv_muts = vec![];
        let mut bool_muts = vec![];
        for (decl, &val) in &self.bvs {
            let v = *other.bvs.get(decl).expect("we just checked that all the keys are the same??");
            if v != val {
                bv_muts.push((decl.apply(&[]).as_bv().unwrap(), v ^ val))
            }
        }
        for (decl, &val) in &self.bools {
            let v = *other.bools.get(decl).expect("we just checked that all the keys are the same????????");
            if v != val {
                bool_muts.push(decl.apply(&[]).as_bool().unwrap());
            }
        }

        ModelMutation::from(bv_muts, bool_muts)
    }
}