use std::collections::{HashMap, HashSet};

use z3::{FuncDecl, AstKind, DeclKind, SatResult};
use z3::ast::{Ast, Dynamic, Bool};
use crate::z3_util::ast_iter::DFSIter;

pub trait SolverWrapper<'ctx> {
    fn solver(&self) -> &z3::Solver<'ctx>;

    fn assert(&mut self, constraint: Bool<'ctx>) {
        self.solver().assert(&constraint);
    }
    fn assert_and_track(&'ctx mut self, constraint: Bool<'ctx>, track: Bool<'ctx>) {
        assert!(track.kind() == AstKind::App && track.decl().kind() == DeclKind::UNINTERPRETED);
        self.solver().assert_and_track(&constraint, &track);

    }
    fn check(&self) -> SatResult {
        self.solver().check()
    }
    fn check_assumptions(&self, assumptions: &[&Bool]) -> SatResult {
        self.solver().check_assumptions(assumptions)
    }

    fn get_context(&self) -> &'ctx z3::Context   {
        self.solver().get_context()
    }
    fn push(&self) {
        self.solver().push()
    }
    fn pop(&self, n: u32) {
        self.solver().pop(n)
    }

    fn get_assertions(&self) -> Vec<z3::ast::Bool<'ctx>> {
        self.solver().get_assertions()
    }

    fn get_reason_unknown(&self) -> Option<String> {
        self.solver().get_reason_unknown()
    }

    fn get_unsat_core(&self) -> Vec<z3::ast::Bool<'ctx>> {
        self.solver().get_unsat_core()
    }

    fn get_model(&self) -> Option<z3::Model<'ctx>> {
        self.solver().get_model()
    }
}
impl<'ctx> SolverWrapper<'ctx> for TrackingSolver<'ctx> {
    fn solver(&self) -> &z3::Solver<'ctx> {
        &self.solver
    }
}
pub struct TrackingSolver<'ctx> {
    solver: z3::Solver<'ctx>,
    pub variables_by_ast_id: HashMap<u32, HashSet<FuncDecl<'ctx>>>,
    pub all_variables: HashSet<FuncDecl<'ctx>>,
}

impl<'ctx> TrackingSolver<'ctx> {
    pub fn new(solver: z3::Solver<'ctx>) -> TrackingSolver<'ctx> {
        TrackingSolver {
            solver: solver,
            variables_by_ast_id: HashMap::new(),
            all_variables: HashSet::new()
        }
    }
    pub fn variables_for(&mut self, ast: &Dynamic<'ctx>) -> &HashSet<FuncDecl> {
        let id = ast.get_ast_id();
        self.variables_by_ast_id.entry(id).or_insert_with(|| {
            let vars = ast.iter_dfs_pre()
                .filter(|x | x.kind() == z3::AstKind::App && x.num_children() == 0)
                .map(|x| x.decl())
                .collect::<HashSet<_>>();
            for v in &vars {
                if !self.all_variables.contains(v) {
                    self.all_variables.insert(v.clone());
                }
            }
            vars
        })
    }
    pub fn variables_for_assertion(&mut self, idx: usize) -> &HashSet<FuncDecl> {
        let assert = self.solver.get_assertions()[idx].clone();
        self.variables_for(&assert.into())
    }
    pub fn assert(&mut self, constraint: Bool<'ctx>) {
        self.solver.assert(&constraint);
        self.variables_for(&constraint.into());
    }
    pub fn assert_and_track(&'ctx mut self, constraint: Bool<'ctx>, track: Bool<'ctx>) {
        assert!(track.kind() == AstKind::App && track.decl().kind() == DeclKind::UNINTERPRETED);
        self.solver.assert_and_track(&constraint, &track);
        self.variables_for(&constraint.into());
        self.variables_for(&track.into());
    }
}