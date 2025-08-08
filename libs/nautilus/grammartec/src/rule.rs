// Nautilus
// Copyright (C) 2024  Daniel Teuchert, Cornelius Aschermann, Sergej Schumilo

extern crate log;

use context::Context;
use newtypes::{NTermID, NodeID, RuleID};
use pyo3::prelude::{PyObject, Python};
use rand::thread_rng;
use rand::Rng;
use regex_syntax::hir::Hir;
use tree::Tree;

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub enum RuleChild {
    Term(Vec<u8>),
    NTerm(NTermID),
}

fn show_bytes(bs: &[u8]) -> String {
    use std::ascii::escape_default;
    use std::str;

    let mut visible = String::new();
    for &b in bs {
        let part: Vec<u8> = escape_default(b).collect();
        visible.push_str(str::from_utf8(&part).unwrap());
    }
    return format!("\"{}\"", visible);
}

impl RuleChild {
    pub fn from_lit(lit: &[u8]) -> Self {
        return RuleChild::Term(lit.into());
    }

    pub fn from_nt(nt: &str, ctx: &mut Context) -> Self {
        if nt.len() >= 3 && nt.starts_with('{') && nt.ends_with('}') {
            let nonterm = &nt[1..nt.len()-1];
            let first_char = nonterm.chars().next().unwrap_or('_');
            if first_char.is_ascii_uppercase() && nonterm.chars().all(|c|
               c.is_ascii_alphanumeric() || "_:@-".contains(c)) {
                return RuleChild::NTerm(ctx.aquire_nt_id(nonterm));
            }
        }
        panic!("Could not interpret Nonterminal {:?}. Nonterminal Descriptions need to start with a capital letter and can only contain [a-zA-Z_:-0-9]", nt);
    }

    fn debug_show(&self, ctx: &Context) -> String {
        match self {
            RuleChild::Term(d) => show_bytes(&d),
            RuleChild::NTerm(nt) => ctx.nt_id_to_s(*nt),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum RuleIDOrCustom {
    Rule(RuleID),
    Custom(RuleID, Vec<u8>),
}
impl RuleIDOrCustom {
    pub fn id(&self) -> RuleID {
        match self {
            RuleIDOrCustom::Rule(id) => return *id,
            RuleIDOrCustom::Custom(id, _) => return *id,
        }
    }

    pub fn data(&self) -> &[u8] {
        match self {
            RuleIDOrCustom::Custom(_, data) => return data,
            RuleIDOrCustom::Rule(_) => panic!("cannot get data on a normal rule"),
        }
    }
}

#[derive(Clone, Debug)]
pub enum Rule {
    Plain(PlainRule),
    Literal(LiteralRule),
    Script(ScriptRule),
    RegExp(RegExpRule),
    Int(IntRule),
    Bytes(BytesRule),
}

#[derive(Debug, Clone)]
pub struct LiteralRule {
    pub nonterm: NTermID,

    // default value of literal
    pub base: Vec<u8>,
}

impl LiteralRule {
    pub fn debug_show(&self, ctx: &Context) -> String {
        return format!("{}:{:?} => bytes({:?})", ctx.nt_id_to_s(self.nonterm), self.nonterm, self.base);
    }
}

#[derive(Debug, Clone)]
pub struct BytesRule {
    pub nonterm: NTermID,
    pub len: usize,
}

impl BytesRule {
    pub fn debug_show(&self, ctx: &Context) -> String {
        return format!("{}:{:?} => bytes({:?})", ctx.nt_id_to_s(self.nonterm), self.nonterm, self.len);
    }
}

#[derive(Debug, Clone)]
pub struct IntRule {
    pub nonterm: NTermID,
    pub bits: usize,
}

impl IntRule {
    pub fn debug_show(&self, ctx: &Context) -> String {
        return format!("{}:{:?} => int({})", ctx.nt_id_to_s(self.nonterm), self.nonterm, self.bits);
    }
}

#[derive(Debug, Clone)]
pub struct RegExpRule {
    pub nonterm: NTermID,
    pub hir: Hir,
}

impl RegExpRule {
    pub fn debug_show(&self, ctx: &Context) -> String {
        return format!("{} => {:?}", ctx.nt_id_to_s(self.nonterm), self.hir);
    }
}

#[derive(Debug)]
pub struct ScriptRule {
    pub nonterm: NTermID,
    pub nonterms: Vec<NTermID>,
    pub script: PyObject,
}

impl ScriptRule {
    pub fn debug_show(&self, ctx: &Context) -> String {
        let args = self
            .nonterms
            .iter()
            .map(|nt| ctx.nt_id_to_s(*nt))
            .collect::<Vec<_>>()
            .join(", ");
        return format!("{} => func({})", ctx.nt_id_to_s(self.nonterm), args);
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct PlainRule {
    pub nonterm: NTermID,
    pub children: Vec<RuleChild>,
    pub nonterms: Vec<NTermID>,
}

impl PlainRule {
    pub fn debug_show(&self, ctx: &Context) -> String {
        let args = self
            .children
            .iter()
            .map(|child| child.debug_show(ctx))
            .collect::<Vec<_>>()
            .join(", ");
        return format!("{} => {}", ctx.nt_id_to_s(self.nonterm), args);
    }
}

impl Clone for ScriptRule {
    fn clone(&self) -> Self {
        return Python::with_gil(|py| {
        ScriptRule {
            nonterm: self.nonterm.clone(),
            nonterms: self.nonterms.clone(),
            script: self.script.clone_ref(py),
        }});
    }
}

impl Rule {
    pub fn from_script(
        ctx: &mut Context,
        nonterm: &str,
        nterms: Vec<String>,
        script: PyObject,
    ) -> Self {
        return Self::Script(ScriptRule {
            nonterm: ctx.aquire_nt_id(nonterm),
            nonterms: nterms.iter().map(|s| ctx.aquire_nt_id(s)).collect(),
            script,
        });
    }

    pub fn from_regex(ctx: &mut Context, nonterm: &str, regex: &str) -> Self {
        use regex_syntax::ParserBuilder;

        let mut parser = ParserBuilder::new()
            .unicode(true)
            .allow_invalid_utf8(true)
            .build();

        let hir = parser.parse(regex).unwrap();

        return Self::RegExp(RegExpRule {
            nonterm: ctx.aquire_nt_id(nonterm),
            hir,
        });
    }

    pub fn debug_show(&self, ctx: &Context) -> String {
        match self {
            Self::Plain(r) => r.debug_show(ctx),
            Self::Literal(r) => r.debug_show(ctx),
            Self::Script(r) => r.debug_show(ctx),
            Self::RegExp(r) => r.debug_show(ctx),
            Self::Int(r) => r.debug_show(ctx),
            Self::Bytes(r) => r.debug_show(ctx),
        }
    }

    pub fn from_format(ctx: &mut Context, nonterm: &str, format: &[u8]) -> Self {
        let children = Rule::tokenize(format, ctx, nonterm);
        let nonterms = children
            .iter()
            .filter_map(|c| {
                if let &RuleChild::NTerm(n) = c {
                    Some(n)
                } else {
                    None
                }
            })
            .collect();
        return Self::Plain(PlainRule {
            nonterm: ctx.aquire_nt_id(nonterm),
            children,
            nonterms,
        });
    }

    pub fn from_literal(ctx: &mut Context, nonterm: &str, term: &[u8]) -> Self {
        return Self::Literal(LiteralRule {
            nonterm: ctx.aquire_nt_id(nonterm),
            base: term.to_vec(),
        });
    }

    pub fn from_bits(ctx: &mut Context, nonterm: &str, bits: usize) -> Self {
        return Self::Int(IntRule {
            nonterm: ctx.aquire_nt_id(nonterm),
            bits: bits,
        });
    }

    pub fn from_bytes(ctx: &mut Context, nonterm: &str, len: usize) -> Self {
        return Self::Bytes(BytesRule {
            nonterm: ctx.aquire_nt_id(nonterm),
            len,
        });
    }

    pub fn unescape(bytes: &[u8]) -> Vec<u8> {
        if bytes.len() < 2 {
            return bytes.to_vec();
        }
        let mut res = vec![];
        let mut i = 0;
        while i < bytes.len() - 1 {
            if bytes[i] == 92 && bytes[i + 1] == 123 {
                // replace \{ with {
                res.push(123);
                i += 1;
            } else if bytes[i] == 92 && bytes[i + 1] == 125 {
                // replace \} with }
                res.push(125);
                i += 1;
            } else {
                res.push(bytes[i]);
            }
            i += 1;
        }
        if i < bytes.len() {
            res.push(bytes[bytes.len() - 1]);
        }
        return res;
    }

    fn tokenize(format: &[u8], ctx: &mut Context, nonterm: &str) -> Vec<RuleChild> {
        #[derive(Copy, Clone)]
        enum State { Outside, Inside }

        let mut state = State::Outside;
        let mut escaped = false;
        let mut buf = Vec::new();
        let mut result = Vec::new();

        for &b in format {
            let c = b as char;

            if escaped {
                // Must be outside or it would throw a panic
                buf.push(b);
                escaped = false;
                continue;
            }

            match (state, c) {
                (State::Outside, '{') => {
                    if !buf.is_empty() {
                        result.push(RuleChild::from_lit(&Self::unescape(&buf)));
                        buf.clear();
                    }
                    state = State::Inside;
                },
                (State::Outside, '}') => panic!("Bad production in rule {}. Unmatched '}}' outside nonterminal. Offending nonterminal: {}", nonterm, std::str::from_utf8(&buf).unwrap_or("N/A")),
                (State::Outside, '\\') => escaped = true,
                (State::Inside, '{') => panic!("Bad production in rule {}. Nested '{{' inside nonterminal. Offending nonterminal: {}", nonterm, std::str::from_utf8(&buf).unwrap_or("N/A")),
                (State::Inside, '}') => {
                    if buf.is_empty() {
                        panic!("Bad production in rule {}. Empty nonterminal is not allowed. Offending nonterminal: {}", nonterm, std::str::from_utf8(&buf).unwrap_or("N/A"));
                    }

                    let nt = format!("{{{}}}", std::str::from_utf8(&buf).expect(format!("Bad production in rule {:?}. Invalid UTF-8", nonterm).as_str()));
                    result.push(RuleChild::from_nt(&nt, ctx));
                    buf.clear();
                    state = State::Outside;
                },
                (State::Inside, '\\') => panic!("Bad production in rule {}. Escape character inside nonterminal", nonterm),
                // Default case
                _ => buf.push(b),
            }
        }

        if escaped {
            panic!("Bad production in rule {}. Production ends with trailing escape character", nonterm);
        }

        if matches!(state, State::Inside) {
            let content = std::str::from_utf8(&buf).unwrap_or("??");
            panic!("Bad production in rule {}. Unclosed nonterminal: {}", nonterm, content);
        }

        if !buf.is_empty() {
            result.push(RuleChild::from_lit(&Self::unescape(&buf)));
        }

        return result;
    }

    pub fn nonterms(&self) -> &[NTermID] {
        return match self {
            Rule::Script(r) => &r.nonterms,
            Rule::Plain(r) => &r.nonterms,
            Rule::Literal(_) => &[],
            Rule::RegExp(_) => &[],
            Rule::Int(_) => &[],
            Rule::Bytes(_) => &[],
        };
    }

    pub fn number_of_nonterms(&self) -> usize {
        return self.nonterms().len();
    }

    pub fn nonterm(&self) -> NTermID {
        return match self {
            Rule::Script(r) => r.nonterm,
            Rule::Literal(r) => r.nonterm,
            Rule::Plain(r) => r.nonterm,
            Rule::RegExp(r) => r.nonterm,
            Rule::Int(r) => r.nonterm,
            Rule::Bytes(r) => r.nonterm,
        };
    }

    pub fn generate(&self, tree: &mut Tree, ctx: &Context, len: usize) -> usize {
        // println!("Rhs: {:?}, len: {}", self.nonterms, len);
        // println!("Min needed len: {}", self.nonterms.iter().fold(0, |sum, nt| sum + ctx.get_min_len_for_nt(*nt) ));
        let minimal_needed_len = self
            .nonterms()
            .iter()
            .fold(0, |sum, nt| sum + ctx.get_min_len_for_nt(*nt));
        assert!(minimal_needed_len <= len);
        let mut remaining_len = len;
        remaining_len -= minimal_needed_len;

        //if we have no further children, we consumed no len
        let mut total_size = 1;
        let paren = NodeID::from(tree.rules.len() - 1);
        //generate each childs tree from the left to the right. That way the only operation we ever
        //perform is to push another node to the end of the tree_vec

        for (i, nt) in self.nonterms().iter().enumerate() {
            //sample how much len this child can use up (e.g. how big can
            //let cur_child_max_len = Rule::get_random_len(remaining_nts, remaining_len) + ctx.get_min_len_for_nt(*nt);
            let mut cur_child_max_len;
            let mut new_nterms = Vec::new();
            new_nterms.extend_from_slice(&self.nonterms()[i..]);
            if new_nterms.len() != 0 {
                cur_child_max_len = ctx.get_random_len(remaining_len, &new_nterms);
            } else {
                cur_child_max_len = remaining_len;
            }
            cur_child_max_len += ctx.get_min_len_for_nt(*nt);

            //get a rule that can be used with the remaining length
            let rid = ctx.get_random_rule_for_nt(*nt, cur_child_max_len);
            log::debug!("Rule: {}, cur_child_max_len: {}, remaining_len: {}", ctx.nt_id_to_s(nt.clone()), cur_child_max_len, remaining_len);
            let rule_or_custom = match ctx.get_rule(rid) {
                Rule::Plain(_) => RuleIDOrCustom::Rule(rid),
                Rule::Script(_) => RuleIDOrCustom::Rule(rid),
                Rule::Literal(LiteralRule { base, .. }) => RuleIDOrCustom::Custom(
                    rid,
                    base.clone(),
                ),
                Rule::RegExp(RegExpRule { hir, .. }) => RuleIDOrCustom::Custom(
                    rid,
                    regex_mutator::generate(hir, thread_rng().gen::<u64>()),
                ),
                Rule::Int(IntRule {bits, ..}) => RuleIDOrCustom::Custom(
                    rid,
                    regex_mutator::dumbass_generator_int(*bits)
                ),
                Rule::Bytes(BytesRule {len, ..}) => RuleIDOrCustom::Custom(
                    rid,
                    regex_mutator::dumbass_generator_bytes(*len)
                ),
            };

            assert_eq!(tree.rules.len(), tree.sizes.len());
            assert_eq!(tree.sizes.len(), tree.paren.len());
            let offset = tree.rules.len();

            tree.rules.push(rule_or_custom);
            tree.sizes.push(0);
            tree.paren.push(NodeID::from(0));

            //generate the subtree for this rule, return the total consumed len
            let consumed_len = ctx.get_rule(rid).generate(tree, ctx, cur_child_max_len - 1);
            tree.sizes[offset] = consumed_len;
            tree.paren[offset] = paren;

            //println!("{}: min_needed_len: {}, Min-len: {} Consumed len: {} cur_child_max_len: {} remaining len: {}, total_size: {}, len: {}", ctx.nt_id_to_s(nt.clone()), minimal_needed_len, ctx.get_min_len_for_nt(*nt), consumed_len, cur_child_max_len, remaining_len, total_size, len);
            assert!(consumed_len <= cur_child_max_len);

            //println!("Rule: {}, min_len: {}", ctx.nt_id_to_s(nt.clone()), ctx.get_min_len_for_nt(*nt));
            assert!(consumed_len >= ctx.get_min_len_for_nt(*nt));

            //we can use the len that where not consumed by this iteration during the next iterations,
            //therefore it will be redistributed evenly amongst the other

            remaining_len += ctx.get_min_len_for_nt(*nt);

            remaining_len -= consumed_len;
            //add the consumed len to the total_len
            total_size += consumed_len;
        }
        //println!("Rule: {}, Size: {}", ctx.nt_id_to_s(self.nonterm.clone()), total_size);
        return total_size;
    }
}
