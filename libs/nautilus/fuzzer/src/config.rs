// Nautilus
// Copyright (C) 2024  Daniel Teuchert, Cornelius Aschermann, Sergej Schumilo

#[derive(Deserialize, Clone)]
pub struct Config {
    pub number_of_threads: u8,
    pub thread_size: usize,
    pub number_of_generate_inputs: u16,
    pub number_of_deterministic_mutations: usize,
    pub max_tree_size: usize,
    pub bitmap_size: usize,
    pub timeout_in_millis: u64,
    pub path_to_bin_target: String,
    pub path_to_grammar: String,
    pub path_to_workdir: String,
    pub arguments: Vec<String>,
    pub num_execs: Option<usize>,
    pub dry_run: Option<bool>,
}
