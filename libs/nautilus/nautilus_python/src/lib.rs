use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyList, PyTuple};
use pyo3::exceptions::{PyException, PyRuntimeError};
use pyo3::create_exception;
use grammartec::context::Context;
use grammartec::newtypes::{RuleID, NodeID};
use grammartec::tree::{Tree, TreeLike};
use grammartec::rule::Rule;
use grammartec::rule::RuleIDOrCustom;
use grammartec::seed_serialization::SerializedSeed;
use grammartec::mutator::Mutator;
use revolver_mutator::{
    get_context_for_input,
    nautilus_serialize_to_bytes,
    nautilus_serialize_to_ron,
    nautilus_deserialize_from_ron,
    nautilus_fuzz_mutate,
};
use fuzzer::python_grammar_loader::load_python_grammar_from_str;
use std::panic::{self, AssertUnwindSafe};
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;

// Create custom Python exceptions
create_exception!(nautilus_python, LoadingError, PyException);
create_exception!(nautilus_python, GenerationError, PyException);

#[pyclass]
pub struct PyGenerator {
    pub ctx: Context,
    pub tree_depth: usize,
    pub grammar_string: String,
    pub grammar_to_context_map: HashMap<String, Context>,
}

#[pymethods]
impl PyGenerator {
    #[staticmethod]
    fn from_string(grammar: &str, tree_depth: usize) -> PyResult<Self> {
        // Use catch_unwind to capture panics
        let result = panic::catch_unwind(AssertUnwindSafe(|| {
            let mut ctx = load_python_grammar_from_str(grammar);
            ctx.initialize(tree_depth);
            PyGenerator {
                ctx: ctx.take_no_anyrule_ctx().unwrap(),
                tree_depth: tree_depth,
                grammar_string: grammar.to_string(),
                grammar_to_context_map: HashMap::<String, Context>::new()
            }
        }));

        match result {
            Ok(generator) => Ok(generator),
            Err(_) => Err(LoadingError::new_err("Grammar parsing failed with a panic in load_python_grammar_from_str"))
        }
    }

    #[staticmethod]
    fn from_file(grammar_path: &str, tree_depth: usize) -> PyResult<Self> {
        let content = std::fs::read_to_string(grammar_path)
            .map_err(|e| LoadingError::new_err(format!("Failed to read grammar file: {}", e)))?;

        let result = panic::catch_unwind(AssertUnwindSafe(|| {
            let mut ctx = load_python_grammar_from_str(&content);
            ctx.initialize(tree_depth);
            PyGenerator {
                ctx: ctx.take_no_anyrule_ctx().unwrap(),
                tree_depth: tree_depth,
                grammar_string: content.to_string(),
                grammar_to_context_map: HashMap::<String, Context>::new()
            }
        }));

        match result {
            Ok(generator) => Ok(generator),
            Err(_) => Err(LoadingError::new_err("Grammar parsing failed with a panic in load_python_grammar_from_str"))
        }
    }

    #[staticmethod]
    fn grammar_to_ron(py: Python, grammar: &str) -> PyResult<Py<PyBytes>> {
        let result = panic::catch_unwind(AssertUnwindSafe(|| {
            let mut ctx = load_python_grammar_from_str(grammar);
            ctx.initialize(200);
            ctx = ctx.take_no_anyrule_ctx().unwrap();
            let nonterm = ctx.nt_id("START");
            let len = ctx.get_random_len_for_nt(&nonterm);
            let generated_tree = ctx.generate_tree_from_nt(nonterm, len); //1 is the index of the "START" Node
            let ron_serialized = nautilus_serialize_to_ron(&SerializedSeed {
                    seed: None,
                    tree: generated_tree.clone(),
                    generation_index: 0,
                    generation_depth: 200,
                    grammar_string: grammar.to_string().clone(),
                    grammar_hash: "aaaaa".to_string(),
                }).expect("Serialization of seed failed!");
            PyBytes::new_bound(py, ron_serialized.as_bytes()).into()
        }));

        match result {
            Ok(ron_serialized) => Ok(ron_serialized),
            Err(_) => Err(GenerationError::new_err("Failed to serialize grammar to RON due to a panic"))
        }
    }

    fn get_rules_repr(&self) -> PyResult<Vec<String>> {
        Ok(self.ctx.get_rules().iter().enumerate().map(|(id, rule)| {
            let ruleclass = match rule {
                Rule::Plain(_) => "PlainRule",
                Rule::Literal(_) => "LiteralRule",
                Rule::Script(_) => "ScriptRule",
                Rule::RegExp(_) => "RegExpRule",
                Rule::Int(_) => "IntRule",
                Rule::Bytes(_) => "BytesRule",
            };
            let nonterm = self.ctx.nt_id_to_s(rule.nonterm());
            format!("{}:{}:{}", id, ruleclass, nonterm)
        }).collect())
    }

    fn get_nt_to_ids(&self) -> PyResult<Vec<(String, usize)>> {
        let mut nt_to_ids = Vec::new();
        // for (id, name) in self.ctx.get_nts().iter() {
        for id in self.ctx.get_nts() {
            let name = self.ctx.nt_id_to_s(id);
            nt_to_ids.push((name, id.to_i()));
        }
        nt_to_ids.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(nt_to_ids)
    }

    fn generate_rule_bytes(&mut self, py: Python, ruleid: usize, count: usize) -> PyResult<Py<PyList>> {
        let result = panic::catch_unwind(AssertUnwindSafe(|| {
            let rule_id = RuleID::from(ruleid);
            let mut seeds: Vec<PyObject> = Vec::with_capacity(count);

            for _ in 0..count {
                let random_len = self.ctx.get_random_len_for_ruleid(&rule_id);
                let generated_tree = self.ctx.generate_tree_from_rule(rule_id, random_len);
                let mut buffer = Vec::new();
                generated_tree.unparse_to(&self.ctx, &mut buffer);
                seeds.push(PyBytes::new_bound(py, &buffer).into());
            }

            PyList::new_bound(py, seeds).into()
        }));

        match result {
            Ok(list) => Ok(list),
            Err(_) => Err(GenerationError::new_err("Failed to generate from rule due to a panic"))
        }
    }

    fn generate_rule_ron(&mut self, py: Python, ruleid: usize, count: usize) -> PyResult<Py<PyList>> {
        let result = panic::catch_unwind(AssertUnwindSafe(|| {
            let rule_id = RuleID::from(ruleid);
            let mut seeds: Vec<PyObject> = Vec::with_capacity(count);

            for _ in 0..count {
                let random_len = self.ctx.get_random_len_for_ruleid(&rule_id);
                let generated_tree = self.ctx.generate_tree_from_rule(rule_id, random_len);
                let ron_serialized = nautilus_serialize_to_ron(&SerializedSeed {
                    seed: None,
                    tree: generated_tree.clone(),
                    generation_index: 0,
                    generation_depth: 200,
                    grammar_string: self.grammar_string.clone(),
                    grammar_hash: "aaaaa".to_string(),
                }).expect("Serialization of seed failed!");
                seeds.push(PyBytes::new_bound(py, ron_serialized.as_bytes()).into());
            }

            PyList::new_bound(py, seeds).into()
        }));

        match result {
            Ok(list) => Ok(list),
            Err(_) => Err(GenerationError::new_err("Failed to generate from rule due to a panic"))
        }
    }

    fn generate_nt_bytes(&mut self, py: Python, ntname: &str, count: usize) -> PyResult<Py<PyList>> {
        let result = panic::catch_unwind(AssertUnwindSafe(|| {
            let ntid = self.ctx.nt_id(ntname);
            let mut seeds: Vec<PyObject> = Vec::with_capacity(count);

            for _ in 0..count {
                let random_len = self.ctx.get_random_len_for_nt(&ntid);
                let generated_tree = self.ctx.generate_tree_from_nt(ntid, random_len);
                for id in 0..generated_tree.size() {
                    let node_id = NodeID::from(id);
                    let _rule_id = generated_tree.get_rule_id(node_id);
                    let _rule_or_custom = generated_tree.get_rule_or_custom(node_id);
                }
                let mut buffer = Vec::new();
                generated_tree.unparse_to(&self.ctx, &mut buffer);
                seeds.push(PyBytes::new_bound(py, &buffer).into());
            }

            PyList::new_bound(py, seeds).into()
        }));

        match result {
            Ok(list) => Ok(list),
            Err(_) => Err(GenerationError::new_err("Failed to generate from non-terminal due to a panic"))
        }
    }

    fn generate_nt_ron(&mut self, py: Python, ntname: &str, count: usize) -> PyResult<Py<PyList>> {
        let result = panic::catch_unwind(AssertUnwindSafe(|| {
            let ntid = self.ctx.nt_id(ntname);
            let mut seeds: Vec<PyObject> = Vec::with_capacity(count);

            for _ in 0..count {
                let random_len = self.ctx.get_random_len_for_nt(&ntid);
                let generated_tree = self.ctx.generate_tree_from_nt(ntid, random_len);
                let ron_serialized = nautilus_serialize_to_ron(&SerializedSeed {
                    seed: None,
                    tree: generated_tree.clone(),
                    generation_index: 0,
                    generation_depth: 200,
                    grammar_string: self.grammar_string.clone(),
                    grammar_hash: "aaaaa".to_string(),
                }).expect("Serialization of seed failed!");
                seeds.push(PyBytes::new_bound(py, ron_serialized.as_bytes()).into());
            }

            PyList::new_bound(py, seeds).into()
        }));

        match result {
            Ok(list) => Ok(list),
            Err(_) => Err(GenerationError::new_err("Failed to generate from non-terminal due to a panic"))
        }
    }

    fn fuzz_wrapper(&mut self, py: Python, input_bytes: &PyBytes) -> PyResult<Py<PyList>> {
        let result = panic::catch_unwind(AssertUnwindSafe( || {
            let mut output: Vec<PyObject> = Vec::new();

            let input_ron: &[u8] = input_bytes.as_bytes();
            let mut input = nautilus_deserialize_from_ron(input_ron).expect("Deserialization failed");
            let ctx = get_context_for_input(&mut self.grammar_to_context_map, &input);
            nautilus_fuzz_mutate(&ctx, &mut input);
            let ron_serialized = nautilus_serialize_to_ron(&input).expect("Serialization of seed failed!");
            let ron_serialized_bytes = ron_serialized.as_bytes();

            let bytes_serialized = nautilus_serialize_to_bytes(&ctx, &input).expect("Serialization to bytes failed!");
            output.push(PyBytes::new_bound(py, ron_serialized_bytes).into());
            output.push(PyBytes::new_bound(py, &bytes_serialized).into());

            PyList::new_bound(py, output).into()
        }));

        match result {
            Ok(mutated_inp) => Ok(mutated_inp),
            Err(_) => Err(GenerationError::new_err("Failed to fuzz due to a panic"))
        }
    }

    fn mutation_wrapper(&mut self, py: Python, input_bytes: &PyBytes) -> PyResult<Py<PyList>> {
        let result = panic::catch_unwind(AssertUnwindSafe( || {
            let mut output: Vec<PyObject> = Vec::new();

            let input_ron: &[u8] = input_bytes.as_bytes();
            let mut input = nautilus_deserialize_from_ron(input_ron).expect("Deserialization failed");
            let ctx = get_context_for_input(&mut self.grammar_to_context_map, &input);

            let mut mutator = Mutator::new(&ctx);
            if let Some(new_tree) = mutator.mutate_tree(&input.tree, &ctx) {
                input.tree = new_tree;
            }

            let ron_serialized = nautilus_serialize_to_ron(&input).expect("Serialization of seed failed!");
            let ron_serialized_bytes = ron_serialized.as_bytes();

            let bytes_serialized = nautilus_serialize_to_bytes(&ctx, &input).expect("Serialization to bytes failed!");
            output.push(PyBytes::new_bound(py, ron_serialized_bytes).into());
            output.push(PyBytes::new_bound(py, &bytes_serialized).into());
            PyList::new_bound(py, output).into()
        }));

        match result {
            Ok(mutated_inp) => Ok(mutated_inp),
            Err(_) => Err(GenerationError::new_err("Failed to mutate due to a panic"))
        }
    }

    fn splice_mutation_wrapper(&mut self, py: Python, input_bytes: &PyBytes, other_bytes: &PyBytes) -> PyResult<Py<PyList>> {
        let result = panic::catch_unwind(AssertUnwindSafe( || {
            let mut output: Vec<PyObject> = Vec::new();

            let input_ron: &[u8] = input_bytes.as_bytes();
            let mut input = nautilus_deserialize_from_ron(input_ron).expect("Deserialization failed");
            let ctx = get_context_for_input(&mut self.grammar_to_context_map, &input);

            let other_ron: &[u8] = other_bytes.as_bytes();
            let mut other_input = nautilus_deserialize_from_ron(other_ron).expect("Deserialization failed");
            let other_ctx = get_context_for_input(&mut self.grammar_to_context_map, &other_input);
            assert_eq!(input.grammar_hash, other_input.grammar_hash, "Grammar hashes do not match!");

            let mut mutator = Mutator::new(&ctx);
            if let Some(new_tree) = mutator.splice_trees(&input.tree, &ctx, &other_input.tree, &other_ctx) {
                input.tree = new_tree;
            }

            let ron_serialized = nautilus_serialize_to_ron(&input).expect("Serialization of seed failed!");
            let ron_serialized_bytes = ron_serialized.as_bytes();

            let bytes_serialized = nautilus_serialize_to_bytes(&ctx, &input).expect("Serialization to bytes failed!");
            output.push(PyBytes::new_bound(py, ron_serialized_bytes).into());
            output.push(PyBytes::new_bound(py, &bytes_serialized).into());
            PyList::new_bound(py, output).into()
        }));

        match result {
            Ok(mutated_inp) => Ok(mutated_inp),
            Err(_) => Err(GenerationError::new_err("Failed to mutate due to a panic"))
        }
    }
}

#[pyclass]
#[derive(Clone, Copy)]
pub struct PyRuleID {
    id: usize,
}

#[pymethods]
impl PyRuleID {
    #[new]
    fn new(id: usize) -> Self {
        Self { id }
    }

    #[getter]
    fn get_id(&self) -> usize {
        self.id
    }

    #[setter]
    fn set_id(&mut self, id: usize) -> PyResult<()> {
        self.id = id;
        Ok(())
    }

    fn __repr__(&self) -> String {
        format!("RuleID({})", self.id)
    }
}

impl PyRuleID {
    fn to_ruleid(&self) -> RuleID {
        RuleID::from(self.id)
    }

    fn from_ruleid(rule_id: &RuleID) -> Self {
        Self { id: rule_id.to_i() }
    }
}

#[pyclass]
#[derive(Clone, Copy)]
pub struct PyNodeID {
    id: usize,
}

#[pymethods]
impl PyNodeID {
    #[new]
    fn new(id: usize) -> Self {
        Self { id }
    }

    #[getter]
    fn get_id(&self) -> usize {
        self.id
    }

    #[setter]
    fn set_id(&mut self, id: usize) -> PyResult<()> {
        self.id = id;
        Ok(())
    }

    fn __repr__(&self) -> String {
        format!("NodeID({})", self.id)
    }
}

impl PyNodeID {
    fn to_nodeid(&self) -> NodeID {
        NodeID::from(self.id)
    }

    fn from_nodeid(node_id: &NodeID) -> Self {
        Self { id: node_id.to_i() }
    }
}

#[pyclass]
#[derive(Clone)]
pub enum PyRuleIDOrCustom {
    Rule { rule_id: PyRuleID },
    Custom { rule_id: PyRuleID, data: Vec<u8> },
}

#[pymethods]
impl PyRuleIDOrCustom {
    #[staticmethod]
    fn rule(rule_id: PyRuleID) -> Self {
        PyRuleIDOrCustom::Rule { rule_id }
    }

    #[staticmethod]
    fn custom(rule_id: PyRuleID, data: Vec<u8>) -> Self {
        PyRuleIDOrCustom::Custom { rule_id, data }
    }

    #[getter]
    fn is_rule(&self) -> bool {
        matches!(self, PyRuleIDOrCustom::Rule { .. })
    }

    #[getter]
    fn is_custom(&self) -> bool {
        matches!(self, PyRuleIDOrCustom::Custom { .. })
    }

    #[getter]
    fn rule_id(&self) -> PyRuleID {
        match self {
            PyRuleIDOrCustom::Rule { rule_id } => *rule_id,
            PyRuleIDOrCustom::Custom { rule_id, .. } => *rule_id,
        }
    }

    #[getter]
    fn custom_data(&self) -> Option<Vec<u8>> {
        match self {
            PyRuleIDOrCustom::Custom { data, .. } => Some(data.clone()),
            _ => None,
        }
    }

    fn __repr__(&self) -> String {
        match self {
            PyRuleIDOrCustom::Rule { rule_id } => {
                format!("RuleIDOrCustom::Rule({})", rule_id.get_id())
            }
            PyRuleIDOrCustom::Custom { rule_id, data } => {
                format!("RuleIDOrCustom::Custom({}, [..{}bytes..])",
                        rule_id.get_id(), data.len())
            }
        }
    }
}

impl PyRuleIDOrCustom {
    fn to_ruleidorcustom(&self) -> RuleIDOrCustom {
        match self {
            PyRuleIDOrCustom::Rule { rule_id } =>
                RuleIDOrCustom::Rule(rule_id.to_ruleid()),
            PyRuleIDOrCustom::Custom { rule_id, data } =>
                RuleIDOrCustom::Custom(rule_id.to_ruleid(), data.clone()),
        }
    }

    fn from_ruleidorcustom(rule: &RuleIDOrCustom) -> Self {
        match rule {
            RuleIDOrCustom::Rule(id) => PyRuleIDOrCustom::Rule {
                rule_id: PyRuleID::from_ruleid(id)
            },
            RuleIDOrCustom::Custom(id, data) => PyRuleIDOrCustom::Custom {
                rule_id: PyRuleID::from_ruleid(id),
                data: data.clone()
            },
        }
    }
}

#[pyclass]
#[derive(Clone)]
pub struct PyTree {
    inner: Tree,
}

#[pymethods]
impl PyTree {

    #[new]
    fn new() -> Self {
        // Create an empty tree
        Self {
            inner: Tree {
                rules: Vec::new(),
                sizes: Vec::new(),
                paren: Vec::new(),
            }
        }
    }

    fn __hash__(&self) -> isize {
        let mut hasher = DefaultHasher::new();
        // Hash rules, sizes, and parent nodes
        for rule in &self.inner.rules {
            match rule {
                RuleIDOrCustom::Rule(id) => (0u8, id.to_i()).hash(&mut hasher),
                RuleIDOrCustom::Custom(id, data) => (1u8, id.to_i(), data).hash(&mut hasher),
            }
        }
        self.inner.sizes.hash(&mut hasher);
        self.inner.paren.iter().map(|id| id.to_i()).for_each(|id| id.hash(&mut hasher));
        hasher.finish() as isize
    }

    fn __eq__(&self, other: &PyAny) -> PyResult<bool> {
        match other.extract::<PyRef<PyTree>>() {
            Ok(other_tree) => Ok(
                self.inner.rules == other_tree.inner.rules &&
                self.inner.sizes == other_tree.inner.sizes &&
                self.inner.paren == other_tree.inner.paren
            ),
            _ => Ok(false)
        }
    }

    #[getter]
    fn get_rules(&self) -> PyResult<Vec<PyRuleIDOrCustom>> {
        let rules = self.inner.rules.iter()
            .map(|r| PyRuleIDOrCustom::from_ruleidorcustom(r))
            .collect();
        Ok(rules)
    }

    #[setter]
    fn set_rules(&mut self, rules: Vec<PyRuleIDOrCustom>) -> PyResult<()> {
        self.inner.rules = rules.iter()
            .map(|r| r.to_ruleidorcustom())
            .collect();
        Ok(())
    }

    #[getter]
    fn get_sizes(&self) -> Vec<usize> {
        self.inner.sizes.clone()
    }

    #[setter]
    fn set_sizes(&mut self, sizes: Vec<usize>) -> PyResult<()> {
        self.inner.sizes = sizes;
        Ok(())
    }

    #[getter]
    fn get_paren(&self) -> PyResult<Vec<PyNodeID>> {
        let paren = self.inner.paren.iter()
            .map(|n| PyNodeID::from_nodeid(n))
            .collect();
        Ok(paren)
    }

    #[setter]
    fn set_paren(&mut self, paren: Vec<PyNodeID>) -> PyResult<()> {
        self.inner.paren = paren.iter()
            .map(|n| n.to_nodeid())
            .collect();
        Ok(())
    }

    fn to_ron_bytes(&self, py: Python) -> PyResult<Py<PyBytes>> {
        let ron_serialized = nautilus_serialize_to_ron(&SerializedSeed {
            seed: None,
            tree: self.inner.clone(),
            generation_index: 0,
            generation_depth: 0,
            grammar_string: String::new(),
            grammar_hash: String::new(),
        }).expect("Serialization of seed failed!");
        let ron_serialized_bytes = ron_serialized.as_bytes();
        Ok(PyBytes::new_bound(py, ron_serialized_bytes).into())
    }
}

#[pyclass]
#[derive(Clone)]
pub struct PySerializedSeed {
    inner: SerializedSeed,
    ctx: Context,
}

#[pymethods]
impl PySerializedSeed {

    #[new]
    fn new() -> Self {
        Self {
            inner: SerializedSeed {
                seed: None,
                tree: Tree {
                    rules: Vec::new(),
                    sizes: Vec::new(),
                    paren: Vec::new(),
                },
                generation_index: 0,
                generation_depth: 0,
                grammar_string: String::new(),
                grammar_hash: String::new(),
            },
            ctx: Context::new(),
        }
    }

    #[getter]
    fn get_seed(&self) -> Option<usize> {
        self.inner.seed
    }

    #[setter]
    fn set_seed(&mut self, seed: Option<usize>) -> PyResult<()> {
        self.inner.seed = seed;
        Ok(())
    }

    #[getter]
    fn get_tree(&self) -> PyResult<PyTree> {
        Ok(PyTree { inner: self.inner.tree.clone() })
    }

    #[setter]
    fn set_tree(&mut self, tree: PyTree) -> PyResult<()> {
        self.inner.tree = tree.inner;
        Ok(())
    }

    #[getter]
    fn get_generation_index(&self) -> usize {
        self.inner.generation_index
    }

    #[setter]
    fn set_generation_index(&mut self, index: usize) -> PyResult<()> {
        self.inner.generation_index = index;
        Ok(())
    }

    #[getter]
    fn get_generation_depth(&self) -> usize {
        self.inner.generation_depth
    }

    #[setter]
    fn set_generation_depth(&mut self, depth: usize) -> PyResult<()> {
        self.inner.generation_depth = depth;
        Ok(())
    }

    #[getter]
    fn get_grammar_string(&self) -> String {
        self.inner.grammar_string.clone()
    }

    #[setter]
    fn set_grammar_string(&mut self, grammar_text: String) -> PyResult<()> {
        self.inner.grammar_string = grammar_text.clone();
        self.inner.grammar_hash = format!("{:x}", md5::compute(&grammar_text));
        let mut ctx = load_python_grammar_from_str(&grammar_text);
        ctx.initialize(self.inner.generation_depth);
        self.ctx = ctx.take_no_anyrule_ctx().unwrap();
        Ok(())
    }

    #[getter]
    fn get_grammar_hash(&self) -> String {
        self.inner.grammar_hash.clone()
    }

    #[staticmethod]
    fn from_ron_bytes(_py: Python, ron_bytes: &PyBytes) -> PyResult<Self> {
        let result = panic::catch_unwind(AssertUnwindSafe(|| {
            let input_bytes = ron_bytes.as_bytes();
            match nautilus_deserialize_from_ron(input_bytes) {
                Ok(seed) => {
                    let mut ctx = load_python_grammar_from_str(&seed.grammar_string);
                    ctx.initialize(seed.generation_depth);
                    Ok(PySerializedSeed { inner: seed, ctx: ctx.take_no_anyrule_ctx().unwrap() })
                },
                Err(_) => Err(PyRuntimeError::new_err("Failed to deserialize RON data"))
            }
        }));

        match result {
            Ok(Ok(seed)) => Ok(seed),
            Ok(Err(err)) => Err(err),
            Err(_) => Err(PyRuntimeError::new_err("Panic occurred while deserializing RON data"))
        }
    }

    fn to_ron_bytes(&self, py: Python) -> PyResult<Py<PyBytes>> {
        let ron_serialized = nautilus_serialize_to_ron(&self.inner).expect("Serialization of seed failed!");
        Ok(PyBytes::new_bound(py, ron_serialized.as_bytes()).into())
    }

    fn unparse_to_vec(&self, py: Python) -> PyResult<Py<PyBytes>> {
        let buffer = self.inner.tree.unparse_to_vec(&self.ctx);
        let node_output_bytes = PyBytes::new_bound(py, &buffer);
        Ok(node_output_bytes.into())
    }

    fn unparse_node_to_vec(&self, py: Python, node_id: usize) -> PyResult<Py<PyBytes>> {
        let node_id = NodeID::from(node_id);
        let node_output = self.inner.tree.unparse_node_to_vec(node_id, &self.ctx);
        let node_output_bytes = PyBytes::new(py, &node_output);
        Ok(node_output_bytes.into())
    }

    fn __repr__(&self) -> String {
        format!("SerializedSeed(seed={:?}, generation_index={}, generation_depth={}, grammar_hash={})",
                self.inner.seed,
                self.inner.generation_index,
                self.inner.generation_depth,
                self.inner.grammar_hash)
    }
}

#[pymodule]
fn nautilus_python(py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<PyGenerator>()?;
    m.add_class::<PySerializedSeed>()?;
    m.add_class::<PyTree>()?;
    m.add_class::<PyRuleID>()?;
    m.add_class::<PyNodeID>()?;
    m.add_class::<PyRuleIDOrCustom>()?;

    // Register exceptions
    m.add("LoadingError", py.get_type_bound::<LoadingError>())?;
    m.add("GenerationError", py.get_type_bound::<GenerationError>())?;

    Ok(())
}
