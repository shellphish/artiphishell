import ast
import hashlib
import networkx as nx
import os
import random
import tempfile

from nautilus_python import PySerializedSeed, PyRuleIDOrCustom, PyRuleID, PyNodeID, PyTree

from morpheus.composable import Composable
from morpheus.grammar import Grammar
from morpheus.rule import LiteralRule, RegExpRule, IntRule, BytesRule, PlainRule
from morpheus.utils import log, exception_wrapper


class DerivationNode:
    def __init__(self, dt=None, rule=None, value=None):
        self.rule = rule
        self.value = value

    def __repr__(self):
        return f"DerivationNode(rule={self.rule}, value={self.value})"

class DerivationTree(Composable):
    def __init__(self):
        super().__init__()
        self.filepath = None

        self.seed = None
        self.tree = None
        self.generation_index = None
        self.generation_depth = None
        self.grammar = None

        self.applied_compositions = None

    @property
    def hexdigest(self):
        ron_bytes = self.to_ron_bytes()
        return hashlib.sha256(ron_bytes).hexdigest()

    # NOTE: we only need rules for compatibility with "Composable" type
    @property
    def rules(self):
        return self.grammar.rules

    @property
    def root(self):
        return next(n for n in self.tree.nodes() if self.tree.in_degree(n) == 0)

    @property
    def nodes(self):
        # return dfs pre-order traversal of the tree
        return list(nx.dfs_preorder_nodes(self.tree, source=self.root))

    @staticmethod
    @exception_wrapper()
    def from_file(filepath):
        with open(filepath, 'rb') as f:
            ron_bytes = f.read()
        return DerivationTree.from_ron_bytes(ron_bytes, filepath)

    @staticmethod
    @exception_wrapper()
    def from_ron_bytes(ron_bytes, filepath):
        dt = DerivationTree()

        ron = PySerializedSeed.from_ron_bytes(ron_bytes)

        # HACK: read and then remove applied compositions from the grammar string
        if ron.grammar_string.startswith("#applied_compositions=["):
            applied_compositions_str = ron.grammar_string.split("\n")[0].split("=")[1]
            dt.applied_compositions = ast.literal_eval(applied_compositions_str)
            ron.grammar_string = "\n".join(ron.grammar_string.split("\n")[1:])
        else:
            dt.applied_compositions = list()

        grammar = Grammar.from_string(ron.grammar_string)
        tree = nx.DiGraph()
        nodes = [DerivationNode(dt=dt) for _ in range(len(ron.tree.rules))]
        for i in range(len(ron.tree.rules)):
            rule_id = ron.tree.rules[i].rule_id.id
            rule = grammar.rules[rule_id]
            nodes[i].rule = rule
            nodes[i].value = ron.unparse_node_to_vec(i)

        for i in range(1, len(ron.tree.rules)):
            parent_id = ron.tree.paren[i].id
            tree.add_edge(nodes[parent_id], nodes[i])
            nodes[i].parent = nodes[parent_id]
        assert len(tree.nodes) == len(ron.tree.rules)
        assert all(len(list(tree.predecessors(node))) == 1 for node in tree.nodes if node != nodes[0])
        assert len(list(tree.predecessors(nodes[0]))) == 0

        dt.filepath = filepath
        dt.tree = tree
        dt.generation_index = ron.generation_index
        dt.generation_depth = ron.generation_depth
        dt.grammar = grammar

        dt.validate()

        return dt

    @exception_wrapper()
    def get_parent(self, node):
        parents = list(self.tree.predecessors(node))
        assert len(parents) <= 1, "Node has more than one parent, which is not allowed in a derivation tree."
        if len(parents) == 0:
            return None
        elif len(parents) == 1:
            return parents[0]

    def serialize_rule(self, node):
        return PyRuleIDOrCustom.Custom(PyRuleID(node.rule.id), node.value) if isinstance(node.rule, (LiteralRule, RegExpRule, IntRule, BytesRule)) else PyRuleIDOrCustom.Rule(PyRuleID(node.rule.id))
        # return PyRuleIDOrCustom.Custom(PyRuleID(node.rule.id), node.value) if node.rule.is_terminal() else PyRuleIDOrCustom.Rule(PyRuleID(node.rule.id))

    def serialize_size(self, node):
        return 1 + len(nx.descendants(self.tree, node))

    def serialize_parent(self, node):
        parent = self.get_parent(node)
        if parent is None:
            return PyNodeID(self.nodes.index(node))
        else:
            return PyNodeID(self.nodes.index(parent))

    def to_pyserialized_seed(self):
        rules = [self.serialize_rule(n) for n in self.nodes]
        # assert [r.__str__() for r in rules] == [r.__str__() for r in ron.tree.rules]
        sizes = [self.serialize_size(n) for n in self.nodes]
        # assert sizes == ron.tree.sizes
        paren = [self.serialize_parent(n) for n in self.nodes]
        # assert [p.__str__() for p in paren] == [p.__str__() for p in ron.tree.paren]

        pytree = PyTree()
        pytree.rules = rules
        pytree.sizes = sizes
        pytree.paren = paren

        pyserialized_seed = PySerializedSeed()
        pyserialized_seed.tree = pytree
        pyserialized_seed.generation_depth = self.generation_depth
        
        grammar_string = self.grammar.serialize()
        grammar_string = f"#applied_compositions={self.applied_compositions}\n{grammar_string}" if self.applied_compositions is not None else grammar_string
        pyserialized_seed.grammar_string = self.grammar.serialize()

        return pyserialized_seed

    def to_ron_bytes(self):
        pyserialized_seed = self.to_pyserialized_seed()
        return pyserialized_seed.to_ron_bytes()

    def insert_subtree_at(self, target_node, subtree):
        subtree_root = next(n for n in subtree.nodes() if subtree.in_degree(n) == 0)

        for node in subtree:
            if node not in self.tree.nodes():
                self.tree.add_node(node)
        for a, b in subtree.edges():
            if (a, b) not in self.tree.edges():
                self.tree.add_edge(a, b)

        # substitute subtrees
        parent = self.get_parent(target_node)
        self.tree.remove_nodes_from(nx.descendants(self.tree, target_node) | {target_node})
        self.tree.add_edge(parent, subtree_root)
        
    @exception_wrapper()
    def iter_single_rule_compositions(self, composition):
        # NOTE: here and below we need to distinguish between rule and nt or else subtree won't be the "whole nt"
        internal_rule = next(r for r in self.grammar.rules if r.hexdigest == composition.internal_rule_hash)

        # CASE 0: rule is not composable
        if not internal_rule.is_composable():
            log.warning(f"Skipping composition for non composable rule {internal_rule.nt}.{internal_rule.id}")
            return

        # CASE 1: no external grammar, just insert the rule
        if composition.external_grammar is None:
            # raise NotImplementedError("Cannot compose rule with no external grammar")
            log.error("Cannot compose rule with no external grammar")
            return

        # CASE 2: external_grammar is reference (reference)
        elif composition.external_grammar.name:
            # easy, splice in a subtree for reference[START]
            assert composition.external_nonterm is not None, "Compositions with reference grammar must specify a nonterm"
            dummy_rule = PlainRule(id=0, namespace=f"EXTERNAL_{composition.external_grammar.name}:", nt=composition.external_nonterm, production=b"", source_code=None, grammar=None)
            new_dt = self.copy()
            new_dt.applied_compositions.append(composition.hexdigest)
            if new_dt.grammar.insert_rule(internal_rule, dummy_rule, encoding=composition.encoding):
                log.info(f"Inserted new rule {internal_rule.nt} -> {dummy_rule.nt}.{dummy_rule.id}" + (f" ({composition.encoding})" if composition.encoding else ""))
                # find last rule with namespace == new_grammar.namespace (new rule) and generate its subtree
                external_rule = next(filter(lambda r: r.namespace == new_dt.grammar.namespace, reversed(new_dt.grammar.rules)))
                external_subtree = next(new_dt.grammar.seed_tree_iterator(rule=external_rule)).tree
                # choose a random node and splice in the subtree
                # NOTE: MAYBE APPLY TO ALL NODES?
                node = random.choice([n for n in new_dt.nodes if n.rule == internal_rule])
                new_dt.insert_subtree_at(node, external_subtree)
                yield new_dt
            else:
                log.error(f"Failed to insert rule {internal_rule.nt} -> {dummy_rule.nt}.{dummy_rule.id}" + (f" ({composition.encoding})" if composition.encoding else ""))
                return

        # CASE 3: external_grammar != internal_grammar (external)
        elif composition.external_grammar.hexdigest != self.grammar.hexdigest:
            # raise NotImplementedError("Cannot compose with external non-reference grammar")
            log.error("Cannot compose with external non-reference grammar")
            return

        # CASE 4: external_grammar == internal_grammar (internal)
        else:
            # raise NotImplementedError("Cannot compose with same grammar")
            log.error("Cannot compose with same grammar")
            return

    def approximate_covered_functions(self, tracer):
        ron = self.to_pyserialized_seed()
        seed = ron.unparse_node_to_vec(0)
        with tempfile.TemporaryDirectory() as tmpdir:
            seed_file = os.path.join(tmpdir, "seed.bin")
            with open(seed_file, "wb") as f:
                f.write(seed)
            covered_functions = tracer.trace(seed_file)
        return covered_functions
            
    @exception_wrapper()
    def validate(self):
        for n in self.nodes:
            if self.tree.out_degree(n) == 0:
                # all leaves are terminal
                assert self.grammar.rules[n.rule.id].is_terminal()
            else:
                # all custom are leaves
                assert not isinstance(self.serialize_rule(n), PyRuleIDOrCustom.Custom)
                # all terminals are leaves
                assert not self.grammar.rules[n.rule.id].is_terminal()

    def copy(self, tree=None, grammar=None, generation_depth=None, applied_compositions=None):
        new_dt = DerivationTree()
        new_dt.tree = tree or self.tree.copy()
        new_dt.grammar = grammar or self.grammar.copy()
        new_dt.generation_depth = generation_depth or self.generation_depth
        new_dt.applied_compositions = applied_compositions or self.applied_compositions.copy() if self.applied_compositions is not None else None
        return new_dt

    def __repr__(self):
        return f"DerivationTree with {len(self.tree.nodes)} nodes"
    