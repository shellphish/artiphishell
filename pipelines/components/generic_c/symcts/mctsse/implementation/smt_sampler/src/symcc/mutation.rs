use std::fmt::{Debug, Display};

use super::model::SymCCModel;

#[derive(Eq, PartialEq, Default, PartialOrd, Ord, Debug, Clone)]
pub struct SymCCMutation {
    pub mutation: Vec<u8>,
}
impl SymCCMutation {
    pub fn new() -> SymCCMutation {
        Default::default()
    }

    pub fn empty(num_bytes: usize) -> SymCCMutation {
        SymCCMutation {
            mutation: (0..num_bytes).map(|_| 0).collect()
        }
    }

    pub fn single_bit(num_bytes: usize, byte_idx: usize, bit_idx: usize) -> SymCCMutation {
        assert!(bit_idx < 8);
        let mut mutation = SymCCMutation::empty(num_bytes);
        mutation.mutation[byte_idx] |= 1 << bit_idx;
        mutation
    }

    pub fn from(mutation: &[u8]) -> SymCCMutation {
        SymCCMutation {
            mutation: mutation.to_vec()
        }
    }
    pub fn from_vec(mutation: Vec<u8>) -> SymCCMutation {
        SymCCMutation {
            mutation
        }
    }

    pub fn combine(&self, other: &SymCCMutation) -> SymCCMutation {
        SymCCMutation {
            mutation: self.mutation.iter().zip(other.mutation.iter()).map(|(x, y)| (x | y)).collect()
        }
    }

    pub fn apply_to_bytes(&self, bytes: &mut [u8]) {
        assert!(self.mutation.len() == bytes.len()); // TODO: <= in the future maybe, but not for now
        for (i, b) in self.mutation.iter().enumerate() {
            bytes[i] ^= b;
        }
    }
    pub fn undo_to_bytes(&self, bytes: &mut [u8]) {
        self.apply_to_bytes(bytes); // undo is just apply again, xor is its own inverse
    }
    pub fn apply_to_model<'ctx>(&self, model: &SymCCModel<'ctx>) -> SymCCModel<'ctx> {
        assert!(model.num_bytes == self.mutation.len());

        let model_bytes = model.concrete_bytes();
        let new_byte_model = model.byte_variables()
            .iter()
            .enumerate()
            .map(|(i, var_ast)| {
                    let cloned = var_ast.clone();
                    if model.is_byte_constrained(i) { // unconstrained inputs should be uniformly random
                        (cloned, Some(self.mutation[i] ^ model_bytes[i]))
                    }
                    else {
                        (cloned, None)
                    }
                })
                .collect::<Vec<_>>();
        SymCCModel::from_vars_and_vals(model.ctx, new_byte_model)
    }
}

impl Display for SymCCMutation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <Self as Debug>::fmt(self, f)
    }
}