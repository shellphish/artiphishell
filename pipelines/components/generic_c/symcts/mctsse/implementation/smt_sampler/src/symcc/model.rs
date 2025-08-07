use std::fmt::{Display, Debug};
use std::hash::Hash;

use bitvec::vec::BitVec;
use z3::{Model, Context};
use z3::ast::{Dynamic, Ast, BV};
use super::mutation::SymCCMutation;

#[derive(Debug, Eq, PartialEq, Clone, Hash)]
pub struct  SymCCModel<'ctx> {
    pub ctx: &'ctx Context,
    pub num_bytes: usize,
    var_asts: Vec<BV<'ctx>>,
    concrete_bytes: Vec<u8>,
    constrained_bytes_bitmap: BitVec
}


impl<'ctx> SymCCModel<'ctx> {
    pub fn assert_vars_have_symcc_names(&self) {
        assert!(self.var_asts.iter().enumerate().all(|(i, var_ast)| {
            let name = var_ast.decl().name().to_string();
            let expected_name = format!("k!{}", i*10);
            assert_eq!(name, expected_name);
            name == expected_name
        }));
    }
    pub fn from_vars_and_vals(ctx: &'ctx Context, vars_and_vals: Vec<(BV<'ctx>, Option<u8>)>) -> SymCCModel<'ctx> {
        let num_vars = vars_and_vals.len();
        let mut var_asts = Vec::with_capacity(num_vars);
        let mut concrete_bytes = Vec::with_capacity(num_vars);
        let mut constrained_bytes_bitmap = BitVec::with_capacity(num_vars);
        for (var_ast, val) in vars_and_vals.into_iter() {
            var_asts.push(var_ast);
            if let Some(val) = val {
                concrete_bytes.push(val);
                constrained_bytes_bitmap.push(true);
            } else {
                concrete_bytes.push(rand::random());
                constrained_bytes_bitmap.push(false);
            }
        }
        let model = SymCCModel {
            ctx,
            num_bytes: num_vars,
            var_asts,
            concrete_bytes,
            constrained_bytes_bitmap
        };
        // model.assert_vars_have_symcc_names();
        model
    }
    pub fn from_model(model: &Model<'ctx>, byte_vars: &[BV<'ctx>]) -> SymCCModel<'ctx> {
        let ctx = model.get_context();
        let vars_and_vals: Vec<(BV<'ctx>, Option<u8>)> = byte_vars.into_iter().map(|var| {
            let decl = var.decl();
            let val = model.get_const_interpretation(&decl).and_then(|x| x.as_bv().map(|x| x.as_u64().unwrap().try_into().unwrap()));
            (var.clone(), val)
        }).collect();
        SymCCModel::from_vars_and_vals(ctx, vars_and_vals)
    }

    pub fn evaluate_slow_substitute_and_simplify(&self, csts: &[&Dynamic<'ctx>]) -> Vec<Dynamic<'ctx>> {
        let val_asts = self.concrete_bytes.iter().map(|&x| BV::from_u64(self.ctx, x as u64, 8)).collect::<Vec<_>>();
        let replacements: Vec<(&BV<'ctx>, &BV<'ctx>)> = (0..self.num_bytes)
            .map(|i| (&self.var_asts[i], &val_asts[i]))
            .collect();
        csts.iter()
            .map(|c| c.substitute(&replacements[..]).simplify())
            .collect()
    }

    pub fn randomize_unconstrained_bytes(&self, num_bytes: usize) -> Vec<u8> {
        // println!("var_asts: {:#?}, num_bytes: {}", self.var_asts, num_bytes);
        assert!(num_bytes >= self.var_asts.len());
        let mut res = self.concrete_bytes.clone();
        for i in 0..res.len() {
            if !*self.constrained_bytes_bitmap.get(i).unwrap() {
                res[i] = rand::random();
            }
        }
        res.resize_with(num_bytes, rand::random);
        return res;
    }

    pub fn byte_variables(&self) -> &[BV<'ctx>] {
        &self.var_asts
    }
    pub fn concrete_bytes(&self) -> &[u8] {
        &self.concrete_bytes
    }

    pub fn is_byte_constrained(&self, i: usize) -> bool {
        self.constrained_bytes_bitmap[i]
    }

    pub fn get_byte_val(&self, byte_idx: usize) -> u8 {
        self.concrete_bytes[byte_idx]
    }
    pub fn get_bit_val(&self, byte_idx: usize, bitidx: usize) -> bool {
        assert!(bitidx < 8);
        (self.concrete_bytes[byte_idx] >> bitidx) & 1 == 1
    }

    pub fn minimal_mutation(&self, other: &SymCCModel<'ctx>) -> SymCCMutation {
        assert!(self.num_bytes == other.num_bytes);
        let muts = (0..self.num_bytes).map(|i| if
                   *self.constrained_bytes_bitmap.get(i).unwrap()
                && *other.constrained_bytes_bitmap.get(i).unwrap()
            {
                // both are constrained, do xor
                self.concrete_bytes[i] ^ other.concrete_bytes[i]
            } else {
                // if either aren't constrained, we don't care
                0
            }).collect::<Vec<_>>();
        SymCCMutation::from_vec(muts)
    }
}


impl<'ctx> PartialOrd for SymCCModel<'ctx> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        assert!(self.ctx == other.ctx);
        if self.num_bytes != other.num_bytes {
            return Some(self.num_bytes.cmp(&other.num_bytes));
        }
        if self.constrained_bytes_bitmap != other.constrained_bytes_bitmap {
            return Some(self.constrained_bytes_bitmap.cmp(&other.constrained_bytes_bitmap));
        }
        if self.concrete_bytes != other.concrete_bytes {
            return Some(self.concrete_bytes.cmp(&other.concrete_bytes));
        }
        for (ast_self, ast_other) in self.var_asts.iter().zip(other.var_asts.iter()) {
            let (name_self, name_other) = (ast_self.get_ast_id(), ast_other.get_ast_id());
            if name_self != name_other {
                return Some(name_self.cmp(&name_other));
            }
        }
        return Some(std::cmp::Ordering::Equal);
    }
}
impl<'ctx> Ord for SymCCModel<'ctx> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.partial_cmp(other).unwrap()
    }
}

impl<'ctx> Display for SymCCModel<'ctx> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <SymCCModel as std::fmt::Debug>::fmt(self, f)
    }
}