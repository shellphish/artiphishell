import hashlib
import networkx as nx
import re

from morpheus.utils import OrderedSet, log


# TODO: check out https://github.com/MozillaSecurity/avalanche for inspiration
class Rule:
    NT_REGEX = re.compile(rb"\{([A-Z][a-zA-Z_:@\-0-9]*)\}")
    def __init__(self, id, namespace, nt, source_code, grammar, children_nts=None):
        self.id = id
        self.namespace = namespace
        if isinstance(namespace, bytes):
            namespace = namespace.decode("utf-8")
        self.nt = nt if isinstance(nt, str) else nt.decode("utf-8")
        self.nt = Rule.apply_namespace(nt, self.namespace)
        self.source_code = source_code
        self.production = None

        self.is_reachable = False
        self.hidden = False

        if grammar is None:
            log.debug("Initializing rule {self.nt}.{self.id} with empty graph")
            self.graph = nx.DiGraph()
        else:
            self.graph = grammar.graph

        self.children_nts = children_nts or list()
        self.children_nts = [nt if isinstance(nt, str) else nt.decode("utf-8") for nt in self.children_nts]
        self.children_nts = [Rule.apply_namespace(nt, self.namespace) for nt in self.children_nts]
        self.children_nts = OrderedSet(self.children_nts)

    @staticmethod
    def apply_namespace(nt, namespace):
        if not namespace:
            return nt
        return f"{namespace}{nt}" if isinstance(nt, str) else namespace.encode("utf-8") + nt

    @staticmethod
    def apply_namespace_to_production(production, namespace):
        return Rule.NT_REGEX.sub(
            lambda m: b"{" + Rule.apply_namespace(m.group(1), namespace) + b"}",
            production
        )

    @property
    def hexdigest(self):
        descendants_shas = [hashlib.sha256(self.source_code.encode()).hexdigest()]
        descendants_shas += sorted([hashlib.sha256(r.source_code.encode()).hexdigest() for r in self.descendants()])
        return hashlib.sha256("|".join(descendants_shas).encode()).hexdigest()

    def is_passthrough(self):
        return (
            isinstance(self, PlainRule) and
            len(self.children_nts) == 1 and
            self.production == b"{" + next(iter(self.children_nts)).encode("utf-8") + b"}"
        )

    def is_literal(self):
        return (
            isinstance(self, PlainRule) and
            len(self.children_nts) == 0
        ) or isinstance(self, LiteralRule)

    def is_terminal(self):
        return (
            isinstance(self, PlainRule) and
            len(self.children_nts) == 0 and
            self.production is not None
        ) or (
            isinstance(self, ScriptRule) and
            len(self.children_nts) == 0
        ) or isinstance(self, (LiteralRule, RegExpRule, IntRule, BytesRule))

    def is_composable(self):
        # never compose on hidden rules
        if self.hidden:
            return False
        # never compose on passthrough rules
        if self.is_passthrough():
            return False
        # never compose on unreachable rules
        # NOTE: should not happen
        # elif not self.is_reachable:
        #     return False
        # never compose on external rules
        elif isinstance(self, ExternalRule):
            return False
        else:
            return True

    def successors(self):
        return self.graph.successors(self)
    
    def predecessors(self):
        return self.graph.predecessors(self)

    def ancestors(self):
        return nx.ancestors(self.graph, self)

    def descendants(self):
        return nx.descendants(self.graph, self)

    def serialize(self):
        return self.source_code

    def __hash__(self):
        return hash(self.__repr__())

    def __eq__(self, other):
        return self.__repr__() == other.__repr__()

    def __repr__(self):
        return f"{self.__class__.__name__}({self.nt}.{self.id}), {self.children_nts=}, {self.source_code=})"

class PlainRule(Rule):
    def __init__(self, id, namespace, nt, production, source_code, grammar, hidden=False):
        # Find referenced nonterminals within braces
        if isinstance(production, str):
            # log.warning(f"Production for {nt=} should be bytes, but is str")
            production = production.encode("utf-8")
        super().__init__(id, namespace, nt, source_code, grammar, children_nts=OrderedSet(Rule.NT_REGEX.findall(production)))
        self.production = Rule.apply_namespace_to_production(production, namespace)
        self.hidden = hidden
        log.debug(f"Adding plain rule for nt: {self.nt}, id: {self.id}, production length: {len(self.production)}")

class LiteralRule(Rule):
    def __init__(self, id, namespace, nt, production, source_code, grammar):
        super().__init__(id, namespace, nt, source_code, grammar)
        self.production = production
        log.debug(f"Adding literal rule for nt: {self.nt}, id: {self.id}, production length: {len(self.production)}")

class RegExpRule(Rule):
    def __init__(self, id, namespace, nt, pattern, source_code, grammar):
        super().__init__(id, namespace, nt, source_code, grammar)
        self.pattern = pattern
        log.debug(f"Adding regex rule for nt: {self.nt}, id: {self.id}, pattern: {self.pattern}")

class ScriptRule(Rule):
    def __init__(self, id, namespace, nt, children_nts, source_code, grammar):
        super().__init__(id, namespace, nt, source_code, grammar, children_nts=OrderedSet(children_nts))
        log.debug(f"Adding script rule for nt: {self.nt}, id: {self.id}, children: {self.children_nts}")


class IntRule(Rule):
    def __init__(self, id, namespace, nt, bits, source_code, grammar):
        super().__init__(id, namespace, nt, source_code, grammar)
        self.bits = bits
        log.debug(f"Adding int rule for nt: {self.nt}, id: {self.id}, bits: {self.bits}")

class BytesRule(Rule):
    def __init__(self, id, namespace, nt, length, source_code, grammar):
        super().__init__(id, namespace, nt, source_code, grammar)
        self.length = length
        log.debug(f"Adding bytes rule for nt: {self.nt}, id: {self.id}, length: {self.length}")

class ExternalRule(Rule):
    def __init__(self, id, namespace, nt, other_namespace, other_nt, other_filepath, source_code, grammar):
        super().__init__(id, namespace, nt, source_code, grammar)
        self.other_namespace = other_namespace
        self.other_nt = other_nt
        self.other_filepath = other_filepath

        self.children_nts= OrderedSet([Rule.apply_namespace(other_nt, other_namespace)])
        log.debug(f"Adding external rule for nt: {self.nt}, id: {self.id}, children: {self.children_nts}")
