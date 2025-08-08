#![allow(deprecated)]
// Nautilus
// Copyright (C) 2024  Daniel Teuchert, Cornelius Aschermann, Sergej Schumilo

extern crate regex;

use pyo3::prelude::*;
use pyo3::types::{IntoPyDict};

use std::io::Write;
use std::path::Path;

use std::collections::{HashSet, VecDeque};

use grammartec::context::Context;
use grammartec::tree::TreeLike;
use grammartec::rule::Rule;

#[pyclass]
struct PyContext {
    ctx: Context,
    namespace: Option<String>,
    imports: Vec<String>,
}

impl PyContext {
    fn get_context(&self) -> Context {
        self.ctx.clone()
    }

    fn add_function_in_scope(&mut self, name: &str, func: PyObject) {
        self.ctx.add_function_in_scope(name, func);
    }

    // Apply the current namespace (if set) to a given nonterminal name.
    fn apply_namespace(&self, nt: &str) -> String {
        match &self.namespace {
            Some(namespace) => format!("{}{}", namespace, nt),
            None => nt.to_string(),
        }
    }

    fn apply_namespace_to_production(&self, production: &[u8]) -> Vec<u8> {
        #[derive(Copy, Clone)]
        enum State { Outside, Inside }
        let mut state = State::Outside;
        let mut escaped = false;
        let mut buf = Vec::new();
        let mut result = Vec::new();
        
        for &b in production {
            let c = b as char;
            if escaped {
                // Must be outside or it would throw a panic
                buf.push(b'\\');
                buf.push(b);
                escaped = false;
                continue;
            }
            match (state, c) {
                (State::Outside, '{') => {
                    if !buf.is_empty() {
                        // Append literal
                        result.extend_from_slice(&buf);
                        buf.clear();
                    }
                    state = State::Inside;
                },
                (State::Outside, '}') => panic!("Bad production. Unmatched '}}' outside nonterminal"),
                (State::Outside, '\\') => escaped = true,
                (State::Inside, '{') => panic!("Bad production. Nested '{{' inside nonterminal"),
                (State::Inside, '}') => {
                    if buf.is_empty() {
                        panic!("Bad production. Empty nonterminal is not allowed");
                    }
                    // Apply namespace and format as {namespaced_nt}
                    let nt = std::str::from_utf8(&buf).expect("Invalid UTF-8 in nonterminal");
                    let namespaced = self.apply_namespace(nt);
                    result.push(b'{');
                    result.extend_from_slice(namespaced.as_bytes());
                    result.push(b'}');
                    buf.clear();
                    state = State::Outside;
                },
                (State::Inside, '\\') => panic!("Bad production. Escape character inside nonterminal"),
                // Default case
                _ => buf.push(b),
            }
        }
        if escaped {
            panic!("Bad production. Production ends with trailing escape character");
        }
        if matches!(state, State::Inside) {
            let content = std::str::from_utf8(&buf).unwrap_or("??");
            panic!("Bad production. Unclosed nonterminal: {}", content);
        }
        if !buf.is_empty() {
            // Append final literal
            result.extend_from_slice(&buf);
        }
        result
    }
}

#[pymethods]
impl PyContext {
    #[new]
    fn new() -> Self {
        PyContext {
            ctx: Context::new(),
            namespace: None,
            imports: Vec::new(),
        }
    }

    fn rule(&mut self, _py: Python, nt: &str, format: &PyAny) -> PyResult<()> {
        let nt_namespaced = self.apply_namespace(nt);
        if let Ok(s) = format.extract::<&str>() {
            let s_namespaced = self.apply_namespace_to_production(s.as_bytes());
            self.ctx.add_rule(&nt_namespaced, &s_namespaced);
        } else if let Ok(s) = format.extract::<&[u8]>() {
            let s_namespaced = self.apply_namespace_to_production(s);
            self.ctx.add_rule(&nt_namespaced, &s_namespaced);
        } else {
            log::error!("Error adding rule '{}': format argument must be string or bytes", nt_namespaced);
            return Err(pyo3::exceptions::PyValueError::new_err("Format argument must be string or bytes"));
        }
        Ok(())
    }

    fn literal(&mut self, _py: Python, nt: &str, value: &PyAny) -> PyResult<()> {
        let nt_namespaced = self.apply_namespace(nt);
        if let Ok(s) = value.extract::<&str>() {
            self.ctx.add_literal(&nt_namespaced, s.as_bytes());
        } else if let Ok(s) = value.extract::<&[u8]>() {
            self.ctx.add_literal(&nt_namespaced, s);
        } else {
            log::error!("Error adding literal '{}': value argument must be string or bytes", nt_namespaced);
            return Err(pyo3::exceptions::PyValueError::new_err("Value argument must be string or bytes"));
        }
        Ok(())
    }

    fn script(&mut self, _py: Python, nt: &str, nts: Vec<String>, script: PyObject) {
        let nt_namespaced = self.apply_namespace(nt);
        let nts_namespaced: Vec<String> = nts.iter().map(|s| self.apply_namespace(s)).collect();
        self.ctx.add_script(&nt_namespaced, nts_namespaced.clone(), script);
        log::debug!("Successfully added script for '{}' with nonterminals: {:?}", nt_namespaced, nts_namespaced);
    }

    fn regex(&mut self, _py: Python, nt: &str, regex: &str) {
        let nt_namespaced = self.apply_namespace(nt);
        self.ctx.add_regex(&nt_namespaced, regex);
        log::debug!("Successfully added regex for '{}': {}", nt_namespaced, regex);
    }

    fn int(&mut self, _py: Python, nt: &str, bits: usize) {
        let nt_namespaced = self.apply_namespace(nt);
        self.ctx.add_int(&nt_namespaced, bits);
        log::debug!("Successfully added int rule for '{}' with {} bits", nt_namespaced, bits);
    }

    fn bytes(&mut self, _py: Python, nt: &str, len: usize) {
        let nt_namespaced = self.apply_namespace(nt);
        self.ctx.add_bytes(&nt_namespaced, len);
        log::debug!("Successfully added bytes rule for '{}' with length {}", nt_namespaced, len);
    }

    fn external(&mut self, py: Python, this_nt: &str, grammar_name: &str, other_nt: Option<&str>, grammar_path: Option<&str>) -> PyResult<()> {
        let other_nt = other_nt.unwrap_or("START");
        // let grammar_path = grammar_path.map(String::from).unwrap_or_else(|| format!("/shellphish/libs/nautilus/grammars/reference/{}.py", grammar_name));
        let nt_namespaced = self.apply_namespace(this_nt);

        let grammar_path = grammar_path.map(String::from).unwrap_or_else(|| {
            let shellphish_path = format!("/shellphish/libs/nautilus/grammars/reference/{}.py", grammar_name);
            let work_path = format!("/work/grammars/reference/{}.py", grammar_name);
            
            if Path::new(&shellphish_path).exists() {
                shellphish_path
            } else if Path::new(&work_path).exists() {
                work_path
            } else {
                log::error!("Grammar file '{}' not found in either shellphish or work directories", grammar_name);
                panic!("Grammar file '{}' not found in either shellphish or work directories", grammar_name);
            }
        });

        let mut other = PyContext {
            ctx: self.ctx.clone(),
            namespace: Some(format!("EXTERNAL_{}:", grammar_name)),
            imports: self.imports.clone(),
        };
        let other_nt_namespaced = other.apply_namespace(other_nt);
        log::debug!("Mapping '{}' to rule '{}' of grammar '{}' from file '{}'", nt_namespaced, other_nt_namespaced, grammar_name, grammar_path);

        if self.imports.contains(&grammar_name.to_string()) {
            log::debug!("Grammar '{}' already loaded", grammar_name);
            self.ctx.add_rule(&nt_namespaced, format!("{{{}}}", other_nt_namespaced).as_bytes());
        } else {
            other.imports.push(grammar_name.to_string());
            log::debug!("Loading external grammar from file '{}'", grammar_path);
            other.ctx.add_rule(&nt_namespaced, format!("{{{}}}", other_nt_namespaced).as_bytes());

            let grammar_content = std::fs::read_to_string(grammar_path)
                .expect("Couldn't read grammar file");
            log::debug!("Grammar file loaded ({} bytes)", grammar_content.len());

            let other_py_ctx = PyCell::new(py, other).unwrap();
            let locals = [("ctx", other_py_ctx)].into_py_dict(py);
            py.run(&grammar_content, None, Some(&locals))?;

            // Collect functions from the external grammar
            for (key, value) in locals.iter() {
                let func_name: String = key.extract()?;
                if value.is_callable() && func_name != "ctx" {
                    other_py_ctx.borrow_mut().add_function_in_scope(func_name.as_str(), value.to_object(py));
                    log::debug!("Function '{}' from external grammar '{}' added to scope", func_name, grammar_name);
                }
            }

            self.ctx = other_py_ctx.borrow().ctx.clone();
            self.imports = other_py_ctx.borrow().imports.clone();
        }

        Ok(())
    }
}

fn _generate_rule(ctx: &Context, ruleid: grammartec::newtypes::RuleID, count: usize) -> Vec<Vec<u8>> {
    (0..count).map(|_| {
        let random_len = ctx.get_random_len_for_ruleid(&ruleid);
        let generated_tree = ctx.generate_tree_from_rule(ruleid, random_len);
        let mut buffer = Vec::new();
        generated_tree.unparse_to(&ctx, &mut buffer);
        buffer
    }).collect()
}

fn find_reachable_nts(ctx: &Context) -> HashSet<grammartec::newtypes::NTermID> {
    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();

    // Add START to visited and queue
    let start_id = ctx.nt_id("START");
    visited.insert(start_id);
    queue.push_back(start_id);

    while let Some(current_nt) = queue.pop_front() {
        // Get rules for current non-terminal
        let rule_ids = ctx.get_rules_for_nt(current_nt);
        for &rule_id in rule_ids {
            // Get non-terminals referenced by each rule
            let rule = ctx.get_rule(rule_id);
            for &nt_id in rule.nonterms() {
                if !visited.contains(&nt_id) {
                    visited.insert(nt_id);
                    queue.push_back(nt_id);
                }
            }
        }
    }
    return visited;
}

fn main_(py: Python, grammar_path: &str) -> PyResult<Context> {
    log::debug!("Loading grammar from file: {}", grammar_path);
    let py_ctx = PyCell::new(py, PyContext::new()).unwrap();
    let locals = [("ctx", py_ctx)].into_py_dict(py);

    let grammar_content = std::fs::read_to_string(grammar_path)
        .expect("Couldn't read grammar file");
    log::debug!("Grammar file loaded ({} bytes)", grammar_content.len());

    py.run(&grammar_content, None, Some(&locals))?;

    // Iterate over the local namespace and collect all callable objects into functions_in_scope
    for (key, value) in locals.iter() {
        let func_name: String = key.extract()?;
        if value.is_callable() {
            py_ctx
                .borrow_mut()
                .add_function_in_scope(func_name.as_str(), value.to_object(py));
            log::debug!("Function '{}' added to scope", func_name);
        }
    }

    // VALIDATE THE GRAMMAR
    let mut ctx = py_ctx.borrow().get_context();
    ctx.initialize(100);

    // let all_nts = ctx.get_nts();
    let nts_with_rules = ctx.get_nts_with_rules();

    // Verify that the grammar has a START rule
    let nts_with_rules_str = nts_with_rules.iter().map(|nt| ctx.nt_id_to_s(*nt)).collect::<Vec<_>>().join(", ");
    if !nts_with_rules_str.contains("START") {
        log::error!("Grammar does not have a START rule");
        return Err(pyo3::exceptions::PyException::new_err("Grammar does not have a START rule"));
    }

    // Verify that all nts are reachable
    let reachable_nts = find_reachable_nts(&ctx);
    // let unreachable_nts: Vec<_> = all_nts.iter().filter(|nt| !reachable_nts.contains(nt)).collect();
    // if !unreachable_nts.is_empty() {
    //     let unreachable_nts_str = unreachable_nts.iter().map(|nt| ctx.nt_id_to_s(**nt)).collect::<Vec<_>>().join(", ");
    //     log::error!("Found unreachable non-terminals: {}", unreachable_nts_str);
    //     return Err(pyo3::exceptions::PyException::new_err(format!("Found unreachable non-terminals: {}", unreachable_nts_str)));
    // }

    // Verify that all reachable rules can generate at least one seed
    for nt in reachable_nts {
        let nt_name = ctx.nt_id_to_s(nt);
        let rule_ids = ctx.get_rules_for_nt(nt);
        for &rule_id in rule_ids {
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let random_len = ctx.get_random_len_for_ruleid(&rule_id);
                let tree = ctx.generate_tree_from_rule(rule_id, random_len);
                let mut buffer = Vec::new();
                tree.unparse_to(&ctx, &mut buffer);
            })) {
                Ok(()) => {},
                _ => {
                    log::error!("Failed to generate seeds for rule '{}'", nt_name.clone());
                    return Err(pyo3::exceptions::PyException::new_err(
                        format!("Failed to generate seeds for rule '{}'", nt_name)
                    ));
                }
            }
        }
    }

    log::debug!("Grammar loaded successfully");
    Ok(py_ctx.borrow().get_context())
}

pub fn load_python_grammar(grammar_path: &str) -> Context {
    log::debug!("Calling load_python_grammar with file: {}", grammar_path);
    Python::with_gil(|py| {
        main_(py, grammar_path).map_err(|e| {
            log::error!("Error in main_ while loading grammar: {:?}", e);
            e.print_and_set_sys_last_vars(py)
        }).unwrap()
    })
}

#[allow(dead_code)]
pub fn load_python_grammar_from_str(grammar: &str) -> Context {
    log::debug!("Loading grammar from provided string");
    // Write grammar to a temporary file.
    let mut tmpfile = tempfile::NamedTempFile::with_suffix(".py")
        .expect("Creating tmp file failed!");
    write!(tmpfile, "{}", grammar)
        .expect("Writing to tmpfile failed!");
    log::debug!("Temporary grammar file created at {:?}", tmpfile.path());

    // Parse that temporary file.
    Python::with_gil(|py| {
        main_(py, &tmpfile.path().to_string_lossy().into_owned()).map_err(|e| {
            log::error!("Error in main_ while loading grammar from string: {:?}", e);
            e.print_and_set_sys_last_vars(py)
        }).unwrap()
    })
}
