use z3::ast::{Ast, Dynamic};

pub trait VerbosePrint<'ctx> {
    fn print_verbose_inner(&self, indent : usize);
    fn print_verbose(&self) {
        self.print_verbose_inner(0)
    }
}

impl<'ctx> VerbosePrint<'ctx> for Dynamic<'ctx> {
    fn print_verbose_inner(&self, indent : usize) {
        let space = " ".repeat(indent * 2);
        println!("{}#####{:?}", space, self);
        println!("{}Kind:        {:?}", space, self.kind());
        println!("{}SortKind:    {:?}", space, self.sort_kind());
        println!("{}Sort:        {:?}", space, self.get_sort());
        println!("{}Decl:        {:?}", space, self.safe_decl());
        if let Ok(decl) = self.safe_decl() {
            println!("{}  name:      {:?}", space, decl.name());
            println!("{}  kind:      {:?}", space, decl.kind());
            println!("{}  arity:     {:?}", space, decl.arity());
            println!("{}  domain:    {:?}", space, decl.domain());
            println!("{}  range:     {:?}", space, decl.range());
            println!("{}  params:    {:?}", space, decl.params());
        }

        println!("{}Children[{}]", space, self.num_children());
        for child in self.children() {
            child.print_verbose_inner(indent+1);
        }
        println!("");

    }
}