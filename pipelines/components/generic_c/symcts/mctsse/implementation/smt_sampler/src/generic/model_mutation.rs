use std::fmt::{Debug, Display};

use sorted_vec::SortedSet;
use z3::ast::{Ast, BV, Bool};

use super::simple_model::SimpleModel;

#[derive(Debug, Eq, PartialEq, PartialOrd, Ord, Clone)]
pub struct BitVectorMutation<'ctx>(BV<'ctx>, u64);


#[derive(Eq, Default, PartialOrd, Ord)]
pub struct ModelMutation<'ctx> {
    bv_muts: SortedSet<BitVectorMutation<'ctx>>,
    bool_muts: SortedSet<Bool<'ctx>>,
}
impl<'ctx> PartialEq for ModelMutation<'ctx> {
    fn eq(&self, other: &Self) -> bool {
        let bv_eq = self.bv_muts == other.bv_muts;
        let bool_eq = self.bool_muts == other.bool_muts;
        let result = bv_eq && bool_eq;
        // println!("eq({:?}, {:?}) = {}, [bv={:?}, bool={:?}]", self, other, result, bv_eq, bool_eq);
        result
    }
}
impl<'ctx> ModelMutation<'ctx> {
    pub fn new() -> ModelMutation<'ctx> {
        Default::default()
    }
    pub fn from(bv_muts: Vec<(BV<'ctx>, u64)>, bool_muts: Vec<Bool<'ctx>>) -> ModelMutation<'ctx> {
        ModelMutation {
            bv_muts: bv_muts.into_iter().map(|(bv,_mut)| BitVectorMutation(bv, _mut)).collect::<Vec<_>>().into(),
            bool_muts: bool_muts.into_iter().collect::<Vec<_>>().into()
        }
    }

    pub fn combine(&self, other: &ModelMutation<'ctx>) -> ModelMutation<'ctx> {
        let combined_bv_muts = self.bv_muts.iter().map(|x| &x.0)
            .chain(other.bv_muts.iter().map(|x| &x.0))
            .map(|bv| {
                let ind_self = self.bv_muts.binary_search_by_key(&bv, |x| &x.0);
                let ind_other = other.bv_muts.binary_search_by_key(&bv, |x| &x.0);
                let val = match (ind_self, ind_other) {
                    (Ok(found_self), Ok(found_other)) => self.bv_muts[found_self].1 | other.bv_muts[found_other].1,
                    (Ok(found_self), Err(_)) => self.bv_muts[found_self].1,
                    (Err(_), Ok(found_other)) => other.bv_muts[found_other].1,
                    (Err(_), Err(_)) => 0
                };
                BitVectorMutation(bv.clone(), val)
            })
            .collect::<Vec<_>>();

        let combined_bool_muts = self.bool_muts.iter().chain(other.bool_muts.iter()).map(|x| x.clone()).collect::<Vec<_>>();

        ModelMutation {
            bv_muts: combined_bv_muts.into(),
            bool_muts: combined_bool_muts.into(),
        }
    }

    pub fn apply(&self, model: &SimpleModel<'ctx>) -> SimpleModel<'ctx> {
        let mut model = model.clone();
        let ctx = model.ctx;

        for mutation in self.bv_muts.iter() {
            let bv = &mutation.0;
            let mutation = mutation.1;
            let const_decl = bv.decl();
            let bv_size = const_decl.range().bv_size().unwrap();
            model.bvs.entry(const_decl.clone()).and_modify(|x| {
                let new = *x ^ mutation;
                model.asts.insert(const_decl, BV::from_u64(ctx, new, bv_size).into());
                *x = new
            });
        }
        for bool_var in self.bool_muts.iter() {
            let const_decl = bool_var.decl();
            model.asts.entry(const_decl.clone()).and_modify(|a| *a = a.as_bool().unwrap().not().simplify().into());
            model.bools.entry(const_decl).and_modify(|x| *x = !*x);
        }
        // println!("model {:?}", model);
        model
    }
}


impl<'ctx> Debug for ModelMutation<'ctx> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let bv_vals = self.bv_muts.iter().map(
            |bv_mut| (
                format!("{:?} {:?}", bv_mut.0, bv_mut.0.get_sort()),
                format!("0x{:x}", bv_mut.1)
            ));
        let bool_vals = self.bool_muts.iter().map(
            |decl| format!("{:?} {:?}", decl, decl.get_sort())
        );
        f.debug_map().entries(bv_vals).finish()?;
        f.debug_set().entries(bool_vals).finish()
    }
}
impl<'ctx> Display for ModelMutation<'ctx> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <Self as Debug>::fmt(self, f)
    }
}
impl<'ctx> Clone for ModelMutation<'ctx> {
    fn clone(&self) -> Self {
        ModelMutation {
            bv_muts: self.bv_muts.clone(),
            bool_muts: self.bool_muts.clone()
        }
    }
}