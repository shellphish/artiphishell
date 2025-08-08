// Nautilus
// Copyright (C) 2024  Daniel Teuchert, Cornelius Aschermann, Sergej Schumilo

use crate::tree::{Tree};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SerializedSeed {
    pub seed: Option<usize>,
    pub tree: Tree,
    pub generation_index: usize,
    pub generation_depth: usize,
    pub grammar_string: String,
    pub grammar_hash: String
}
