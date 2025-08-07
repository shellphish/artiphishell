use z3::ast::{Ast, Dynamic};
use z3::{AstKind, DeclKind};
use std::collections::HashSet;

#[cfg(test)]
mod tests {
    use z3::ast::{Ast, Dynamic, Bool};
    use crate::z3_util::ast_visitor::consts;
    use crate::z3_util::ast_verbose_print::VerbosePrint;

    #[test]
    fn consts_test_regression() {
        let cfg = z3::Config::new();
        let ctx = z3::Context::new(&cfg);
        let x = z3::ast::Bool::from_bool(&ctx, true);

        let x_dyn: z3::ast::Dynamic = x.into();

        let result = consts(&x_dyn);
        if result.len() != 0 {
            let dy: Dynamic= Bool::new_const(&ctx, "asdf").into();
            dy.print_verbose();
            x_dyn.print_verbose();
            assert!(false, "Expected to get no variables back, got {:?}", result);
        }
    }
}

pub fn consts<'ctx>(ast: &Dynamic<'ctx>) -> HashSet<Dynamic<'ctx>> {
    let mut to_visit = vec![];
    to_visit.push(ast.clone());
    let mut visited = HashSet::<u32>::new();
    let mut result = HashSet::new();
    while let Some(cur) = to_visit.pop() {
        let cur_id = cur.get_ast_id();
        if visited.contains(&cur_id) {
            continue;
        }

        visited.insert(cur_id);
        let mut children = cur.children();
        if children.len() > 0 {
            to_visit.append(&mut children);
            assert!(!cur.is_const(), "how does a const have children??");
            continue;
        }
        if cur.kind() != AstKind::App {
            continue;
        }
        let decl = cur.decl();
        assert!(decl.arity() == 0);
        if decl.kind() == DeclKind::UNINTERPRETED {
            // uninterpreted == variable
            result.insert(cur);
        }
        else {
            assert!(decl.kind() == DeclKind::TRUE || decl.kind() == DeclKind::FALSE, "unknown const decl kind: {:?}", decl.kind());
        }

    }
    result
}

// pub struct ConstsVisitor<'ctx> {
//     pub consts: HashSet<Dynamic<'ctx>>
// }
// impl<'ctx> ConstsVisitor<'ctx> {
//     pub fn new() -> Self {
//         ConstsVisitor {
//             consts: HashSet::new()
//         }
//     }
// }
// impl<'ctx> AstVisitor<'ctx> for ConstsVisitor<'ctx> {
//     fn visit_App(&mut self, ast: &Dynamic<'ctx>) {
//         if ast.num_children() == 0 {
//             let decl = ast.decl();
//             assert!(decl.arity() == 0);
//             self.consts.insert(ast.clone());
//         }
//     }
// }