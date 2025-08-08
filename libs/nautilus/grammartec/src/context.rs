// Nautilus
// Copyright (C) 2024  Daniel Teuchert, Cornelius Aschermann, Sergej Schumilo

extern crate log;

use std::collections::HashMap;

use rand::{thread_rng, Rng};
use rand::seq::IteratorRandom;

use newtypes::{NTermID, RuleID};
use pyo3::prelude::PyObject;
use rule::{Rule, RuleChild, RuleIDOrCustom};
use tree::Tree;

#[derive(Clone, Default)]
pub struct Context {
    rules: Vec<Rule>,
    nts_to_rules: HashMap<NTermID, Vec<RuleID>>,
    nt_ids_to_name: HashMap<NTermID, String>,
    names_to_nt_id: HashMap<String, NTermID>,
    rules_to_min_size: HashMap<RuleID, usize>,

    nts_to_min_size: HashMap<NTermID, usize>,

    rules_to_num_options: HashMap<RuleID, usize>,
    nts_to_num_options: HashMap<NTermID, usize>,
    max_len: usize,

    functions_in_scope: HashMap<String, PyObject>,

    no_anyrule_ctx: Option<Box<Context>>,
}

impl Context {
    pub fn new() -> Self {
        Context::default()
    }

    pub fn initialize(&mut self, max_len: usize) {
        let mut nt_names: Vec<(NTermID, String)> = self.nt_ids_to_name.clone().into_iter().collect::<Vec<_>>();
        nt_names.sort_by(|(nt1, _), (nt2, _)| (<NTermID as Into<usize>>::into(*nt1)).cmp(&(<NTermID as Into<usize>>::into(*nt2))));
        let any_nonterm = self.aquire_nt_id("ANYRULE");

        for (_nt_id, nt_name) in nt_names.clone() {
            let nonterm = self.aquire_nt_id(&nt_name);

            let any_rid: RuleID = self.rules.len().into();
            let any_rule = Rule::Plain(crate::rule::PlainRule {
                nonterm: any_nonterm,
                nonterms: vec![nonterm],
                children: vec![RuleChild::NTerm(nonterm)],
            });
            self.rules.push(any_rule);
            self.nts_to_rules
                .entry(any_nonterm)
                .or_default()
                .push(any_rid);
        }

        let mut no_anyrule_ctx = self.clone();
        no_anyrule_ctx.calc_min_len();
        no_anyrule_ctx.calc_num_options();
        no_anyrule_ctx.max_len = max_len + 2;
        self.no_anyrule_ctx = Some(Box::new(no_anyrule_ctx));

        for (_nt_id, nt_name) in nt_names {
            let rid: RuleID = self.rules.len().into();
            let nonterm = self.aquire_nt_id(&nt_name);
            let new_rule = Rule::Plain(crate::rule::PlainRule {
                nonterm,
                nonterms: vec![any_nonterm],
                children: vec![RuleChild::NTerm(any_nonterm)],
            });
            self.rules.push(new_rule);
            self.nts_to_rules
                .entry(nonterm)
                .or_default()
                .push(rid);
        }

        self.calc_min_len();
        self.calc_num_options();
        self.max_len = max_len + 2;
    }

    pub fn get_no_anyrule_ctx(&self) -> &Option<Box<Context>> {
        &self.no_anyrule_ctx
    }

    pub fn take_no_anyrule_ctx(&mut self) -> Option<Context> {
        self.no_anyrule_ctx.take().map(|boxed| *boxed)
    }

    pub fn get_rule(&self, r: RuleID) -> &Rule {
        let id: usize = r.into();
        return &self.rules[id];
    }

    pub fn get_rules(&self) -> &Vec<Rule> {
        return &self.rules;
    }

    pub fn get_nt(&self, r: &RuleIDOrCustom) -> NTermID {
        return self.get_rule(r.id()).nonterm();
    }

    pub fn get_nts(&self) -> Vec<NTermID> {
        return self.nt_ids_to_name.keys().cloned().collect();
    }

    pub fn get_nts_with_rules(&self) -> Vec<NTermID> {
        return self.nts_to_rules.keys().cloned().collect();
    }

    pub fn get_num_children(&self, r: &RuleIDOrCustom) -> usize {
        return self.get_rule(r.id()).number_of_nonterms();
    }

    pub fn add_function_in_scope(&mut self, name: &str, func: PyObject) -> () {
        if !self.functions_in_scope.contains_key(name) {
            self.functions_in_scope.insert(name.to_string(), func);
        }
    }

    pub fn get_functions_in_scope(&self) -> &HashMap<String, PyObject> {
        return &self.functions_in_scope;
    }

    pub fn add_rule(&mut self, nt: &str, format: &[u8]) -> RuleID {
        let rid: RuleID = self.rules.len().into();
        log::debug!("Adding plain rule for nt: {}, id {:?}", nt, rid);
        let rule = Rule::from_format(self, nt, format);
        let ntid = self.aquire_nt_id(nt);
        self.rules.push(rule);
        self.nts_to_rules
            .entry(ntid)
            .or_insert_with(|| vec![])
            .push(rid);
        return rid;
    }

    pub fn add_script(&mut self, nt: &str, nts: Vec<String>, script: PyObject) -> RuleID {
        let rid: RuleID = self.rules.len().into();
        assert!(nts.len() > 0, "script rules need at least one nonterminal, but rule {} has none", nt);
        log::debug!("Adding script rule for nt: {}, id {:?}", nt, rid);
        let rule = Rule::from_script(self, nt, nts, script);
        let ntid = self.aquire_nt_id(nt);
        self.rules.push(rule);
        self.nts_to_rules
            .entry(ntid)
            .or_insert_with(|| vec![])
            .push(rid);
        return rid;
    }

    pub fn add_regex(&mut self, nt: &str, regex: &str) -> RuleID {
        let rid: RuleID = self.rules.len().into();
        log::debug!("Adding regex rule for nt: {}, id {:?}", nt, rid);
        let rule = Rule::from_regex(self, nt, regex);
        let ntid = self.aquire_nt_id(nt);
        self.rules.push(rule);
        self.nts_to_rules
            .entry(ntid)
            .or_insert_with(|| vec![])
            .push(rid);
        return rid;
    }

    pub fn add_int(&mut self, nt: &str, bits: usize) -> RuleID {
        let rid = self.rules.len().into();
        log::debug!("Adding int rule for nt: {}, id {:?}", nt, rid);
        let rule = Rule::from_bits(self, nt, bits);
        let ntid = self.aquire_nt_id(nt);
        self.rules.push(rule);
        self.nts_to_rules
            .entry(ntid)
            .or_insert_with(|| vec![])
            .push(rid);
        return rid;
    }

    pub fn add_bytes(&mut self, nt: &str, len: usize) -> RuleID {
        let rid = self.rules.len().into();
        log::debug!("Adding bytes rule for nt: {}, id {:?}", nt, rid);
        let rule = Rule::from_bytes(self, nt, len);
        let ntid = self.aquire_nt_id(nt);
        self.rules.push(rule);
        self.nts_to_rules
            .entry(ntid)
            .or_insert_with(|| vec![])
            .push(rid);
        return rid;
    }

    pub fn add_literal(&mut self, nt: &str, term: &[u8]) -> RuleID {
        let rid: RuleID = self.rules.len().into();
        log::debug!("Adding literal rule for nt: {}, id {:?}", nt, rid);
        let rule = Rule::from_literal(self, nt, term);
        let ntid = self.aquire_nt_id(nt);
        self.rules.push(rule);
        self.nts_to_rules
            .entry(ntid)
            .or_insert_with(|| vec![])
            .push(rid);
        return rid;
    }

    pub fn aquire_nt_id(&mut self, nt: &str) -> NTermID {
        let next_id = self.nt_ids_to_name.len().into();
        let id = self.names_to_nt_id.entry(nt.into()).or_insert(next_id);
        self.nt_ids_to_name.entry(*id).or_insert(nt.into());
        return *id;
    }

    pub fn nt_id(&self, nt: &str) -> NTermID {
        return *self
            .names_to_nt_id
            .get(nt)
            .expect(&("No such nonterminal: ".to_owned() + nt));
    }

    pub fn nt_id_to_s(&self, nt: NTermID) -> String {
        return self.nt_ids_to_name[&nt].clone();
    }

    fn calc_min_len_for_rule(&self, r: RuleID) -> Option<usize> {
        let mut res = 1;
        for nt_id in self.get_rule(r).nonterms().iter() {
            if let Some(min) = self.nts_to_min_size.get(nt_id) {
                // println!("Calculating length for Rule(calc_min_len_for_rule): {}, current: {}, adding: {}, because of rule: {}", self.nt_id_to_s(self.get_rule(r).nonterm().clone()), res, min, self.nt_id_to_s(nt_id.clone()));
                res += *min;
            } else {
                return None;
            }
        }
        // println!("Calculated length for Rule(calc_min_len_for_rule): {}, Length: {}", self.nt_id_to_s(self.get_rule(r).nonterm().clone()), res);
        return Some(res);
    }

    pub fn calc_min_len(&mut self) {
        let mut something_changed = true;
        while something_changed == true {
            //TODO: find a better solution to prevent  consumed_len >= ctx.get_min_len_for_nt(*nt)' Assertions
            let mut unknown_rules = (0..self.rules.len())
                .map(|i| RuleID::from(i))
                .collect::<Vec<_>>();
            something_changed = false;
            while unknown_rules.len() > 0 {
                let last_len = unknown_rules.len();
                unknown_rules.retain(|rule| {
                    if let Some(min) = self.calc_min_len_for_rule(*rule) {
                        let nt = self.get_rule(*rule).nonterm();
                        // let name = self.nt_id_to_s(nt.clone()); //DEBUGGING
                        let e = self.nts_to_min_size.entry(nt).or_insert(min);
                        if *e > min {
                            *e = min;
                            something_changed = true;
                        }
                        // println!("Calculated length for Rule: {}, Length: {}, Min_length_of_nt: {}", name, min, *e);
                        self.rules_to_min_size.insert(*rule, min);
                        false
                    } else {
                        true
                    }
                });
                if last_len == unknown_rules.len() {
                    log::error!("Found unproductive rules: (missing base/non recursive case?)");
                    for r in unknown_rules {
                        log::error!("{}", self.get_rule(r).debug_show(&self));
                    }
                    panic!("Broken Grammar");
                }
            }
        }
        self.calc_rule_order();
    }

    fn calc_num_options_for_rule(&self, r: RuleID) -> usize {
        let mut res = 1_usize;
        for nt_id in self.get_rule(r).nonterms().iter() {
            res = res.saturating_mul(*self.nts_to_num_options.get(nt_id).unwrap_or(&1));
        }
        return res;
    }

    pub fn calc_num_options(&mut self) {
        for (nt, rules) in self.nts_to_rules.iter() {
            self.nts_to_num_options.entry(*nt).or_insert(rules.len());
        }

        let mut something_changed = true;
        while something_changed == true {
            something_changed = false;

            for rid in (0..self.rules.len()).map(|i| RuleID::from(i)) {
                let num = self.calc_num_options_for_rule(rid);
                let nt = self.get_rule(rid).nonterm();
                let e = self.nts_to_num_options.entry(nt).or_insert(num);
                if *e < num {
                    *e = num;
                    something_changed = true;
                }
                //println!("Calculated length for Rule: {}, Length: {}, Min_length_of_nt: {}", name, min, *e);
                self.rules_to_num_options.insert(rid, num);
            }
        }
    }

    fn calc_rule_order(&mut self) {
        let rules_to_min_size = &self.rules_to_min_size;
        for rules in self.nts_to_rules.values_mut() {
            (*rules).sort_by(|r1, r2| rules_to_min_size[r1].cmp(&rules_to_min_size[r2]));
        }
    }

    pub fn check_if_rule_has_multiple_values(&self, rule: &Rule) -> bool {
        matches!(rule, Rule::Int(_) | Rule::Bytes(_) | Rule::RegExp(_) | Rule::Literal(_))
    }

    pub fn check_if_nterm_has_multiple_values(&self, nt: &NTermID) -> bool {
        for ruleid in self.get_rules_for_nt(*nt) {
            let rule = self.get_rule(*ruleid);
            match rule {
                Rule::Int(_) => {
                    return true;
                },
                Rule::Bytes(_) => {
                    return true;
                },
                Rule::RegExp(_) => {
                    return true;
                },
                _ => {
                    continue;
                }
            }
        }
        return false;

    }

    pub fn check_if_nterm_has_multiple_possiblities(&self, nt: &NTermID) -> bool {
        return self.get_rules_for_nt(*nt).len() > 1;
    }

    pub fn get_random_len(&self, len: usize, rhs_of_rule: &Vec<NTermID>) -> usize {
        return self.dumb_get_random_len(rhs_of_rule.len(), len);
    }

    //we need to get maximal sizes for all subtrees. To generate trees fairly, we want to split the
    //available size fairly to all nodes. (e.g. all children have the same expected size,
    //regardless of its index in the current rule. We use this version of the algorithm described
    //here: https://stackoverflow.com/a/8068956 to get the first value.
    fn dumb_get_random_len(&self, number_of_children: usize, total_remaining_len: usize) -> usize {
        let mut res = total_remaining_len;
        let iters = (number_of_children as i32) - 1;
        for _ in 0..iters {
            let proposal = thread_rng().gen_range(0..total_remaining_len + 1);
            if proposal < res {
                res = proposal;
            }
        }
        return res;
    }

    pub fn get_min_len_for_nt(&self, nt: NTermID) -> usize {
        return self.nts_to_min_size[&nt];
    }

    pub fn get_random_rule_for_nt(&self, nt: NTermID, len: usize) -> RuleID {
        return self.dumb_get_random_rule_for_nt(nt, len);
    }

    pub fn get_applicable_rules(
        &self,
        max_len: usize,
        nt: NTermID,
        p_include_short_rules: usize,
    ) -> impl Iterator<Item = &RuleID> {
        return self.nts_to_rules[&nt]
            .iter()
            .take_while(move |r| self.rules_to_min_size[r] <= max_len)
            .filter(move |r| {
                self.rules_to_num_options[r] > 1
                    || (thread_rng().gen::<usize>() % 100) <= p_include_short_rules
            });
    }

    fn dumb_get_random_rule_for_nt(&self, nt: NTermID, max_len: usize) -> RuleID {
        let p_include_short_rules = if self.nts_to_num_options[&nt] < 10 {
            100
        } else if max_len > 100 {
            2
        } else if max_len > 20 {
            50
        } else {
            100
        };

        if let Some(opt) = self.get_applicable_rules(max_len, nt, p_include_short_rules)
            .choose(&mut thread_rng())
        {
            *opt
        } else if let Some(opt) =
            self.get_applicable_rules(max_len, nt, 100).choose(&mut thread_rng())
        {
            *opt
        } else {
            panic!(
                "there is no way to derive {} within {} steps",
                self.nt_ids_to_name[&nt], max_len
            )
        }
    }

    pub fn get_random_len_for_ruleid(&self, _rule_id: &RuleID) -> usize {
        return self.max_len; //TODO?????
    }

    pub fn get_random_len_for_nt(&self, _nt: &NTermID) -> usize {
        return self.max_len;
    }

    pub fn get_rules_for_nt(&self, nt: NTermID) -> &Vec<RuleID> {
        return &self.nts_to_rules[&nt];
    }

    pub fn generate_tree_from_nt(&self, nt: NTermID, max_len: usize) -> Tree {
        return self.generate_tree_from_rule(self.get_random_rule_for_nt(nt, max_len), max_len - 1);
    }

    pub fn generate_tree_from_rule(&self, r: RuleID, len: usize) -> Tree {
        let mut tree = Tree::from_rule_vec(vec![], self);
        tree.generate_from_rule(r, len, self);
        return tree;
    }
}

#[cfg(test)]
mod tests {
    use context::Context;
    use rule::{Rule, RuleChild, RuleIDOrCustom};
    use tree::{Tree, TreeLike};

    #[test]
    fn simple_context() {
        let mut ctx = Context::new();
        let r = Rule::from_format(&mut ctx, "F", b"foo{A:a}\\{bar\\}{B:b}asd{C}");
        let soll = vec![
            RuleChild::from_lit(b"foo"),
            RuleChild::from_nt("{A:a}", &mut ctx),
            RuleChild::from_lit(b"{bar}"),
            RuleChild::from_nt("{B:b}", &mut ctx),
            RuleChild::from_lit(b"asd"),
            RuleChild::from_nt("{C}", &mut ctx),
        ];
        if let Rule::Plain(rl) = &r {
            assert_eq!(&rl.children, &soll);
        } else {
            unreachable!();
        }
        assert_eq!(r.nonterms()[0], ctx.nt_id("A"));
        assert_eq!(r.nonterms()[1], ctx.nt_id("B"));
        assert_eq!(r.nonterms()[2], ctx.nt_id("C"));
    }

    #[test]
    fn test_context() {
        let mut ctx = Context::new();
        let r0 = ctx.add_rule("C", b"c{B}c");
        let r1 = ctx.add_rule("B", b"b{A}b");
        let _ = ctx.add_rule("A", b"a {A}");
        let _ = ctx.add_rule("A", b"a {A}");
        let _ = ctx.add_rule("A", b"a {A}");
        let _ = ctx.add_rule("A", b"a {A}");
        let _ = ctx.add_rule("A", b"a {A}");
        let r3 = ctx.add_rule("A", b"a");
        ctx.initialize(5);
        assert_eq!(ctx.get_min_len_for_nt(ctx.nt_id("A")), 1);
        assert_eq!(ctx.get_min_len_for_nt(ctx.nt_id("B")), 2);
        assert_eq!(ctx.get_min_len_for_nt(ctx.nt_id("C")), 3);
        let mut tree = Tree::from_rule_vec(vec![], &ctx);
        tree.generate_from_nt(ctx.nt_id("C"), 3, &ctx);
        assert_eq!(
            tree.rules,
            vec![
                RuleIDOrCustom::Rule(r0),
                RuleIDOrCustom::Rule(r1),
                RuleIDOrCustom::Rule(r3),
            ]
        );
        let mut data: Vec<u8> = vec![];
        tree.unparse_to(&ctx, &mut data);
        assert_eq!(String::from_utf8(data).expect("RAND_3377050372"), "cbabc");
    }

    #[test]
    fn test_generate_len() {
        let mut ctx = Context::new();
        let r0 = ctx.add_rule("E", b"({E}+{E})");
        let r1 = ctx.add_rule("E", b"({E}*{E})");
        let r2 = ctx.add_rule("E", b"({E}-{E})");
        let r3 = ctx.add_rule("E", b"({E}/{E})");
        let r4 = ctx.add_rule("E", b"1");
        ctx.initialize(11);
        assert_eq!(ctx.get_min_len_for_nt(ctx.nt_id("E")), 1);

        for _ in 0..100 {
            let mut tree = Tree::from_rule_vec(vec![], &ctx);
            tree.generate_from_nt(ctx.nt_id("E"), 9, &ctx);
            assert!(tree.rules.len() < 10);
            assert!(tree.rules.len() >= 1);
        }

        let rules = vec![r0, r1, r4, r4, r4]
            .iter()
            .map(|x| RuleIDOrCustom::Rule(*x))
            .collect::<Vec<_>>();
        let tree = Tree::from_rule_vec(rules, &ctx);
        let mut data: Vec<u8> = vec![];
        tree.unparse_to(&ctx, &mut data);
        assert_eq!(
            String::from_utf8(data).expect("RAND_3492562908"),
            "((1*1)+1)"
        );

        let rules = vec![r0, r1, r2, r3, r4, r4, r4, r4, r4]
            .iter()
            .map(|x| RuleIDOrCustom::Rule(*x))
            .collect::<Vec<_>>();
        let tree = Tree::from_rule_vec(rules, &ctx);
        let mut data: Vec<u8> = vec![];
        tree.unparse_to(&ctx, &mut data);
        assert_eq!(
            String::from_utf8(data).expect("RAND_4245419893"),
            "((((1/1)-1)*1)+1)"
        );
    }
}
