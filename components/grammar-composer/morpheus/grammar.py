import base64
import ast
import functools
import hashlib
import inspect
import itertools
import json
import random
import networkx as nx
import os
import tempfile

from collections import defaultdict
from functools import partial

from nautilus_python import PyGenerator, GenerationError

from morpheus.composable import Composable
from morpheus.config import REFERENCE_GRAMMARS_FILEPATHS
from morpheus.fingerprint import RuleFingerprint
from morpheus.rule import Rule, PlainRule, LiteralRule, RegExpRule, ScriptRule, IntRule, BytesRule, ExternalRule
from morpheus.utils import OrderedSet, exception_wrapper, log

ARTIPHISHELL_HELPER_FUNCTIONS = dict()
ARTIPHISHELL_HELPER_FUNCTIONS["artiphishell_base64_encode"] = "def artiphishell_base64_encode(data: bytes) -> bytes:\n    import base64\n    return base64.b64encode(data)"


with open("/shellphish//grammar-composer/reference_fingerprints.json") as f:
    REFERENCE_FINGERPRINTS = json.load(f)

with open("/shellphish//grammar-composer/reference_rulehashes.json") as f:
    REFERENCE_RULEHASHES = json.load(f)
    REFERENCE_RULEHASHES = {k: set(v) for k, v in REFERENCE_RULEHASHES.items()}

class Grammar(Composable):
    def __init__(self, name):
        self.name = name
        self.namespace = f"EXTERNAL_{name}:" if name else ""
        self.imports = set()

        # NOTE: the order of rules is important to validate equivalence with nautilus
        self.rules = []
        self.nts = OrderedSet()
        self.nt_to_rules = defaultdict(set)
        self.helper_functions = ARTIPHISHELL_HELPER_FUNCTIONS.copy()

        self.graph = nx.DiGraph()

        self.tree_depth = None
        self.generator = None
        self._source_code_ast = None

    @property
    def start_rules(self):
        start_nt = Rule.apply_namespace("START", self.namespace)
        return {rule for rule in self.rules if rule.nt == start_nt}

    @property
    def hexdigest(self):
        return hashlib.sha256(self.serialize().encode()).hexdigest()

    def rule(self, nt, production):
        lineno = inspect.currentframe().f_back.f_lineno
        rule_ast = next(filter(lambda r: r.lineno == lineno, self._source_code_ast.body))
        source_code = ast.unparse(rule_ast)

        rule = PlainRule(len(self.rules), self.namespace, nt, production, source_code, self)
        log.debug(f"Adding PlainRule: namespace={self.namespace}, nt={nt}, production={production}, rule_id={rule.id}")
        self.rules.append(rule)
        self.nts.update(rule.children_nts)
        self.nts.add(rule.nt)
        self.nt_to_rules[rule.nt].add(rule)
        log.debug(f"Current NTs in grammar: {sorted(self.nts)}")

    def literal(self, nt, production):
        lineno = inspect.currentframe().f_back.f_lineno
        rule_ast = next(filter(lambda r: r.lineno == lineno, self._source_code_ast.body))
        source_code = ast.unparse(rule_ast)

        rule = LiteralRule(len(self.rules), self.namespace, nt, production, source_code, self)
        log.debug(f"Adding LiteralRule: namespace={self.namespace}, nt={nt}, production={production}, rule_id={rule.id}")
        self.rules.append(rule)
        self.nts.add(rule.nt)
        self.nt_to_rules[rule.nt].add(rule)

    def regex(self, nt, pattern):
        lineno = inspect.currentframe().f_back.f_lineno
        rule_ast = next(filter(lambda r: r.lineno == lineno, self._source_code_ast.body))
        source_code = ast.unparse(rule_ast)

        rule = RegExpRule(len(self.rules), self.namespace, nt, pattern, source_code, self)
        log.debug(f"Adding RegExpRule: namespace={self.namespace}, nt={nt}, pattern={pattern}, rule_id={rule.id}")
        self.rules.append(rule)
        self.nts.add(rule.nt)
        self.nt_to_rules[rule.nt].add(rule)

    def script(self, nt, children_nts, script_content):
        lineno = inspect.currentframe().f_back.f_lineno
        rule_ast = next(filter(lambda r: r.lineno == lineno, self._source_code_ast.body))
        source_code = ast.unparse(rule_ast)

        rule = ScriptRule(len(self.rules), self.namespace, nt, children_nts, source_code, self)
        log.debug(f"Adding ScriptRule: namespace={self.namespace}, nt={nt}, children_nts={children_nts}, rule_id={rule.id}")
        self.rules.append(rule)
        self.nts.update(rule.children_nts)
        self.nts.add(rule.nt)
        self.nt_to_rules[rule.nt].add(rule)

    def int(self, nt, bits):
        lineno = inspect.currentframe().f_back.f_lineno
        rule_ast = next(filter(lambda r: r.lineno == lineno, self._source_code_ast.body))
        source_code = ast.unparse(rule_ast)

        rule = IntRule(len(self.rules), self.namespace, nt, bits, source_code, self)
        log.debug(f"Adding IntRule: namespace={self.namespace}, nt={nt}, bits={bits}, rule_id={rule.id}")
        self.rules.append(rule)
        self.nts.add(rule.nt)
        self.nt_to_rules[rule.nt].add(rule)

    def bytes(self, nt, length):
        lineno = inspect.currentframe().f_back.f_lineno
        rule_ast = next(filter(lambda r: r.lineno == lineno, self._source_code_ast.body))
        source_code = ast.unparse(rule_ast)

        rule = BytesRule(len(self.rules), self.namespace, nt, length, source_code, self)
        log.debug(f"Adding BytesRule: namespace={self.namespace}, nt={nt}, length={length}, rule_id={rule.id}")
        self.rules.append(rule)
        self.nts.add(rule.nt)
        self.nt_to_rules[rule.nt].add(rule)

    def external(self, nt, external_grammar_name, external_nt=None, other_filepath=None):
        from morpheus.config import REFERENCE_GRAMMARS_DIR
        
        lineno = inspect.currentframe().f_back.f_lineno
        rule_ast = next(filter(lambda r: r.lineno == lineno, self._source_code_ast.body))
        source_code = ast.unparse(rule_ast)

        external_namespace = f"EXTERNAL_{external_grammar_name}:"
        external_nt = external_nt or "START"
        other_filepath = other_filepath or f"{REFERENCE_GRAMMARS_DIR}/{external_grammar_name}.py"

        rule = ExternalRule(len(self.rules), self.namespace, nt, external_namespace, external_nt, other_filepath, source_code, self)
        log.debug(f"Adding ExternalRule: namespace={self.namespace}, nt={nt}, external_namespace={external_namespace}, external_nt={external_nt}, rule_id={rule.id}")
        self.rules.append(rule)
        self.nts.update(rule.children_nts)
        self.nts.add(rule.nt)
        self.nt_to_rules[rule.nt].add(rule)

        if external_grammar_name not in self.imports:
            log.debug(f"Importing external grammar: {external_grammar_name} from {other_filepath}")
            self.imports.add(external_grammar_name)

            with open(other_filepath) as f:
                other_source_code = f.read()

            saved_namespace = self.namespace
            saved_source_code_ast = self._source_code_ast

            log.debug(f"Switching namespace from {self.namespace} to {external_namespace}")
            self.namespace = external_namespace
            self._source_code_ast = ast.parse(other_source_code, filename=other_filepath)
            exec(other_source_code, {}, {"ctx": self})

            log.debug(f"Restoring namespace from {self.namespace} to {saved_namespace}")
            self.namespace = saved_namespace
            self._source_code_ast = saved_source_code_ast
            
            log.debug(f"Finished importing {external_grammar_name}. Current NTs: {sorted([nt for nt in self.nts if nt.startswith(external_namespace)])}")
    
    def get_rules_repr(self):
        return [
            f"{r.id}:"
            f"{r.__class__.__name__.replace('ExternalRule', 'PlainRule')}:"
            f"{r.nt[len(self.namespace):] if (r.namespace and (r.namespace == self.namespace) and r.nt != 'ANYRULE') else r.nt}"
            for r in self.rules
        ]

    @classmethod
    @exception_wrapper()
    def from_file(cls, filepath, tree_depth=250):
        return cls._from_file(name=None, filepath=filepath, tree_depth=tree_depth)

    @classmethod
    @exception_wrapper()
    def _from_file(cls, name, filepath, tree_depth=250):
        log.debug(f"Loading grammar {name} from filepath {filepath}")
        with open(filepath) as f:
            source_code = f.read()
        return cls._from_string(name, source_code, filepath, tree_depth)
    
    @classmethod
    @exception_wrapper()
    def from_string(cls, source_code, filepath="<string>", tree_depth=250):
        return cls._from_string(name=None, source_code=source_code, filepath=filepath, tree_depth=tree_depth)

    @classmethod
    @exception_wrapper()
    def _from_string(cls, name, source_code, filepath="<string>", tree_depth=250):
        log.debug(f"Loading grammar {name} from string")
        grammar = cls(name)
        grammar.tree_depth = tree_depth

        # Capture helper functions.
        # NOTE: must happen before executing the source code
        log.debug("Parsing the source code")
        grammar._source_code_ast = ast.parse(source_code, filename=filepath)
        log.debug("Capturing helper functions")
        for rule_ast in grammar._source_code_ast.body:
            if isinstance(rule_ast, ast.FunctionDef):
                function_name = rule_ast.name
                function_body = ast.unparse(rule_ast)
                grammar.helper_functions[function_name] = function_body
    
        # Execute the grammar file in a controlled namespace
        log.debug("Executing the source code with the grammar context")
        exec(source_code, {}, {"ctx": grammar})

        # Initialize the generator object
        log.debug("Initializing the (Rust) PyGenerator object")
        grammar.generator = PyGenerator.from_string(source_code, tree_depth)

        if grammar.name is None:
            nts = [nt for nt, id in sorted(dict(grammar.generator.get_nt_to_ids()).items(), key=lambda item: item[1]) if nt != "ANYRULE"]
        else:
            nts = [nt for nt, id in sorted(dict(grammar.generator.get_nt_to_ids()).items(), key=lambda item: item[1]) if nt != "ANYRULE" and ":" not in nt]
            nts = [f"{grammar.namespace}{nt}" for nt in nts]  # add the namespace to the non-terminals

        # Add ANYRULE non-terminal
        log.debug("Adding ANYRULES to the grammar")
        grammar.nts.add("ANYRULE")

        # First pass: Add all ANYRULE -> nt rules
        for nt in nts:
            namespace = nt.split(":")[0]+":" if ":" in nt else None
            anyrule = PlainRule(id=len(grammar.rules), namespace=None, nt="ANYRULE", production=f"{{{nt}}}", source_code="", grammar=grammar, hidden=True)
            anyrule.namespace = namespace  # HACK: Ensure the ANYRULE has the correct namespace (without applying the namespace again)
            log.debug(f"Adding ANYRULE: {anyrule}")
            grammar.rules.append(anyrule)
            grammar.nt_to_rules["ANYRULE"].add(anyrule)

        # Second pass: Add all nt -> ANYRULE rules  
        # for nt in nts:
        #     namespace = nt.split(":")[0]+":" if ":" in nt else None
        #     reverse_anyrule = PlainRule(id=len(grammar.rules), namespace=None, nt=nt, production="{ANYRULE}", source_code="", grammar=grammar, hidden=True)
        #     reverse_anyrule.namespace = namespace  # HACK: Ensure the reverse ANYRULE has the correct namespace (without applying the namespace again)
        #     log.debug(f"Adding reverse ANYRULE: {reverse_anyrule}")
        #     grammar.rules.append(reverse_anyrule)
        #     grammar.nt_to_rules[nt].add(reverse_anyrule)

        # Construct the graph of the grammar.
        log.debug("Constructing the control flow graph")
        for rule in grammar.rules:
            grammar.graph.add_node(rule)
        for a in grammar.rules:
            for nt in a.children_nts:
                for b in grammar.nt_to_rules[nt]:
                    grammar.graph.add_edge(a, b)

        # Mark all reachable rules
        reachable_rules = grammar.start_rules | set.union(*[set(nx.descendants(grammar.graph, rule)) for rule in grammar.start_rules])
        for rule in reachable_rules:
            rule.is_reachable = True

        grammar.validate()
        return grammar

    @exception_wrapper()
    def widen(self):
        # for each nonterminal, add a new rule nonterminal -> ctx.bytes(???)
        for rule in self.rules:
            if isinstance(rule, BytesRule):
                continue
            sample_value = next(self.seed_iterator(rule=rule))
            dummy_rule = BytesRule(
                id=len(self.rules),
                namespace=self.namespace,
                nt=rule.nt,
                length=len(sample_value),
                source_code=f"""ctx.bytes("{rule.nt}", {len(sample_value)})""",
                grammar=self
            )
            self.rules.append(dummy_rule)
            self.nts.add(dummy_rule.nt)
            self.nt_to_rules[dummy_rule.nt].add(dummy_rule)

        source_code = self.serialize()
        new_grammar = Grammar._from_string(self.name, source_code, tree_depth=self.tree_depth)
        self.__dict__.update(new_grammar.__dict__)
        return True

    @exception_wrapper()
    def insert_rule(self, internal_rule, external_rule, encoding=None):
        internal_nt = internal_rule.nt
        log.debug(f"Inserting external rule {external_rule.nt} into internal non-terminal {internal_nt}")
        assert external_rule.namespace, f"Unsupported insert without a namespace"
        assert external_rule.nt.startswith("EXTERNAL_"), f"Non namespaced external nt. How did this happen?"

        external_namespace = external_rule.namespace
        external_grammar_name = external_namespace.replace("EXTERNAL_", "")[:-1]  # remove the trailing colon
        external_nt = external_rule.nt.split(":")[1]

        if internal_rule.hexdigest in REFERENCE_RULEHASHES.get(f"{external_namespace}{external_nt}", set()):
            log.warning(f"Rule {internal_nt} already exists in the grammar. Skipping insertion.")
            return False

        encoding_rule = None
        if encoding is not None:
            encoded_internal_nt = internal_nt
            internal_nt = f"artiphishell_non_encoded_{external_grammar_name}".upper()
            encoding_function = f"artiphishell_{encoding}_encode"
            assert encoding_function in self.helper_functions, f"Encoding function {encoding_function} not found in the grammar."
            source_code = f"""ctx.script("{encoded_internal_nt}", ["{internal_nt}"], lambda data, encode={encoding_function}: encode(data))\n"""
            encoding_rule = ScriptRule(len(self.rules), self.namespace, encoded_internal_nt, [internal_nt], source_code, self)

        if any(isinstance(r, ExternalRule) and r.nt == internal_nt and r.other_namespace == external_namespace and r.other_nt == external_nt for r in self.rules):
            log.warning(f"Rule {internal_nt} already exists in the grammar. Skipping insertion.")
            return False

        source_code = f"ctx.external(\"{internal_nt}\", \"{external_grammar_name}\", \"{external_nt}\")"
        splicing_rule = ExternalRule(len(self.rules), self.namespace, internal_nt, external_namespace, external_nt, None, source_code, self)

        self.rules.append(splicing_rule)
        self.nts.add(splicing_rule.nt)
        self.nt_to_rules[splicing_rule.nt].add(splicing_rule)

        # NOTE: the composition_log in grammar.iter_compositions() relies on the order of rules appended
        if encoding_rule is not None:
            self.rules.append(encoding_rule)
            self.nts.add(encoding_rule.nt)
            self.nt_to_rules[encoding_rule.nt].add(encoding_rule)

        # NOTE: We need to get a new generator object and load external rules, reloading is usually cheap
        # not always, see slow-grammar.py for an example
        try:
            new_source_code = self.serialize()
            new_grammar = Grammar._from_string(self.name, new_source_code, tree_depth=self.tree_depth)
            self.__dict__.update(new_grammar.__dict__)
        except:
            log.error(f"Failed to reload the grammar after inserting rule {internal_nt}. Probably the new grammar failed to load.")
            return False

        return True

    @exception_wrapper()
    def seed_iterator(self, nt=None, rule=None, batch_size=5, n=None, force=False):
        if nt is None and rule is None:
            nt = "START"
        elif nt is not None and rule is not None:
            raise ValueError("Exactly one of 'nt' or 'rule' must be specified")  
        elif rule is not None and rule not in self.rules:
            raise ValueError("Rule not in grammar")
        elif nt is not None and nt not in self.nts:
            raise ValueError("Non-terminal not in grammar")

        # skip generation if .is_literal() --> we know exactly what this rule generates
        if rule is not None and rule.is_literal():
            yield rule.production if isinstance(rule.production, bytes) else rule.production.encode()
            return
        elif nt is not None and all(r.is_literal() for r in self.nt_to_rules[nt]):
            for rule in self.nt_to_rules[nt]:
                yield rule.production if isinstance(rule.production, bytes) else rule.production.encode()
            return
            
        seen = set()
        empty_batches = 0
        max_empty_batches = 3

        GENERATOR = partial(self.generator.generate_nt_bytes, nt) if nt else partial(self.generator.generate_rule_bytes, rule.id)
        # NOTE: functools.update_wrapper copies name, docstring, etc. to the wrapper function
        functools.update_wrapper(GENERATOR, self.generator.generate_nt_bytes if nt else self.generator.generate_rule_bytes)
        GENERATOR = exception_wrapper(exception_types=GenerationError, returnval=iter([]))(GENERATOR)
        
        while empty_batches < max_empty_batches:
            new_found = False
            for seed_bytes in GENERATOR(batch_size):
                if seed_bytes not in seen:
                    seen.add(seed_bytes)
                    new_found = True
                    yield seed_bytes

                    if n is not None and len(seen) >= n:
                        return
                    
            empty_batches = 0 if new_found else empty_batches + 1
            
    @exception_wrapper()
    def seed_iterator_map(self, map_fn, nt=None, rule=None, batch_size=5, n=None):
        seen = set()
        empty_batches = 0
        max_empty_batches = 3

        ITERATOR = self.seed_iterator(nt, rule, batch_size)
        
        while empty_batches < max_empty_batches:
            new_found = False
            for output in map_fn(itertools.islice(ITERATOR, batch_size)):
                if output not in seen:
                    seen.add(output)
                    new_found = True
                    yield output
                    
                    if n is not None and len(seen) >= n:
                        return
                    
            empty_batches = 0 if new_found else empty_batches + 1

    @exception_wrapper()
    def seed_tree_iterator(self, nt=None, rule=None, batch_size=5, n=None, force=False):
        from morpheus.derivation_tree import DerivationTree

        if nt is None and rule is None:
            nt = "START"
        elif nt is not None and rule is not None:
            raise ValueError("Exactly one of 'nt' or 'rule' must be specified")  
        elif rule is not None and rule not in self.rules:
            raise ValueError("Rule not in grammar")
        elif nt is not None and nt not in self.nts:
            raise ValueError("Non-terminal not in grammar")
            
        seen = set()
        empty_batches = 0
        max_empty_batches = 3

        GENERATOR = partial(self.generator.generate_nt_ron, nt) if nt else partial(self.generator.generate_rule_ron, rule.id)
        # NOTE: functools.update_wrapper copies name, docstring, etc. to the wrapper function
        functools.update_wrapper(GENERATOR, self.generator.generate_nt_ron if nt else self.generator.generate_rule_ron)
        GENERATOR = exception_wrapper(exception_types=GenerationError, returnval=iter([]))(GENERATOR)
        
        while empty_batches < max_empty_batches:
            new_found = False
            for seed_ron_bytes in GENERATOR(batch_size):
                seed_dt = DerivationTree.from_ron_bytes(seed_ron_bytes, None)

                if seed_dt is None:
                    log.warning("Failed to parse seed RON bytes into a DerivationTree. Skipping.")
                    continue
                
                if seed_dt not in seen:
                    seen.add(seed_dt)
                    new_found = True
                    yield seed_dt

                    if n is not None and len(seen) >= n:
                        return
                    
            empty_batches = 0 if new_found else empty_batches + 1

    def approximate_prefixes(self, nt=None, rule=None, batch_size=5, n=None):
        def seeds_to_prefixes(seeds):
            return [s[:4] for s in seeds if len(s) >= 4]
        return self.seed_iterator_map(seeds_to_prefixes, nt=nt, rule=rule, batch_size=batch_size, n=n)

    def approximate_suffixes(self, nt=None, rule=None, batch_size=5, n=None):
        def seeds_to_suffixes(seeds):
            return [s[-4:] for s in seeds if len(s) >= 4]
        return self.seed_iterator_map(seeds_to_suffixes, nt=nt, rule=rule, batch_size=batch_size, n=n)

    def approximate_covered_functions(self, tracer, batch_size=5, n=None):
        def seeds_to_covered_functions(seeds):
            with tempfile.TemporaryDirectory() as tmpdir:
                seed_files = []
                for i, seed in enumerate(seeds):
                    filename = os.path.join(tmpdir, f"seed-{i}.bin")
                    with open(filename, "wb") as f:
                        f.write(seed)
                    seed_files.append(filename)
                if seed_files:
                    covered_functions = tracer.trace(*seed_files)
                else:
                    log.warning("Could not generate any seeds, returning empty list. Weird.")
                    covered_functions = []
            return covered_functions
        return self.seed_iterator_map(seeds_to_covered_functions, batch_size=batch_size, n=n)
        
    @exception_wrapper()
    def validate(self):
        # Ensure that all non-terminals are defined.
        for rule in self.rules:
            log.debug(f"Validating rule: {rule}")
            for nt in rule.children_nts:
                assert nt in self.nts, f"Non-terminal {nt} is not defined."

        # Ensure that generator.get_rules_repr matches exactly with self.get_rules_repr
        assert self.generator.get_rules_repr() == self.get_rules_repr(), f"Generator rules do not match grammar rules. Generator rules: {self.generator.get_rules_repr()}. Grammar rules: {self.get_rules_repr()}"

    @exception_wrapper()
    def serialize(self):
        serialized_rules = [r.serialize() for r in self.rules if r.namespace == self.namespace and not r.hidden]

        sep = "#" * 70
        lines = []
        if self.helper_functions:
            lines.extend([sep, "# Helper Functions", sep, ""])
            for _, body in sorted(self.helper_functions.items()):
                lines.extend([body, ""])
        lines.extend([sep, "# Grammar Rules", sep, ""])
        lines.extend([*serialized_rules, ""])

        return "\n".join(lines)

    @exception_wrapper()
    def iter_compositions(self, confidence_threshold=1.0, token_quality_threshold=0.5, composition_log=None):
        for replacements in self.iter_composition_replacements(max_samples=10, confidence_threshold=confidence_threshold, token_quality_threshold=token_quality_threshold):
            new_grammar = self.copy()
            is_changed = False

            for internal_rule, external_grammar_name, external_grammar_nt, encoding in replacements:
                if internal_rule.hidden:
                    log.debug(f"Skipping hidden rule {internal_rule.nt} -> {external_grammar_name}.{external_grammar_nt}")
                    continue
                # TODO: support other non-reference grammars, if needed
                if external_grammar_name in REFERENCE_GRAMMARS_FILEPATHS:
                    dummy_reference_rule = PlainRule(id=0, namespace=f"EXTERNAL_{external_grammar_name}:", nt=external_grammar_nt, production=b"", source_code=None, grammar=None)
                    if new_grammar.insert_rule(internal_rule, dummy_reference_rule, encoding=encoding):
                        log.info(f"Inserted new rule {internal_rule.nt} -> {dummy_reference_rule.nt}.{dummy_reference_rule.id}" + (f" ({encoding})" if encoding else ""))
                        is_changed = True
                        # find last rule with namespace == new_grammar.namespace
                        external_rule = next(filter(lambda r: r.namespace == new_grammar.namespace, reversed(new_grammar.rules)))
                        if composition_log is not None:
                            composition_log.append((internal_rule, external_rule, external_grammar_name))
                    else:
                        log.error(f"Failed to insert rule {internal_rule.nt} -> {dummy_reference_rule.nt}.{dummy_reference_rule.id}" + (f" ({encoding})" if encoding else ""))

            if composition_log is not None:
                composition_log.clear()

            if is_changed:
                yield new_grammar

    @exception_wrapper()
    def iter_composition_replacements(self, max_samples, confidence_threshold=1.0, token_quality_threshold=0.5):
        # deduplicate (internal_rule.nt, external) -- we don't care about confidence and rules with the same nt
        all_rule_composition_candidates = set()
        seen_pairs = set()
        for internal_rule in self.rules:
            if not internal_rule.is_composable():
                continue
            seeds = list(self.seed_iterator(rule=internal_rule, n=50))

            # FROM FINGERPRINT
            fp = RuleFingerprint()
            for seed in seeds:
                prefix = seed[:4]
                fp.update(prefix.ljust(4, b'\x00'))
            # NOTE: SEEDS ARE DEDUPED SO WE FORCE AS MANY OBSERVATIONS AS THE NUMBER OF REQUESTED SEEDS
            fp.num_observations = 50

            log.debug(f"Rule {internal_rule.nt}.{internal_rule.id} fingerprint: {fp.to_hex()}")
            if fp.num_observations >= 5 and fp.to_hex() in REFERENCE_FINGERPRINTS:
                log.debug(f"Rule {internal_rule.nt}.{internal_rule.id} matches reference fingerprints: {REFERENCE_FINGERPRINTS[fp.to_hex()]}")
                for external_grammar_name, external_grammar_nt, encoding in REFERENCE_FINGERPRINTS[fp.to_hex()]:
                    log.info(f"[fingerprint] Rule {internal_rule.nt}.{internal_rule.id} matches {external_grammar_name}:{external_grammar_nt} with encoding {encoding}")
                    external = (external_grammar_name, external_grammar_nt)
                    if (internal_rule.nt, external, encoding) not in seen_pairs:
                        seen_pairs.add((internal_rule.nt, external, encoding))
                        all_rule_composition_candidates.add((internal_rule, external, 1.0, encoding))

            # FROM MAGIC SIMILARITY
            for external_grammar_name, external_grammar_nt, confidence in self.magic_similarity(seeds, confidence_threshold, token_quality_threshold):
                log.info(f"[magic_similarity] Rule {internal_rule.nt}.{internal_rule.id} matches {external_grammar_name}:{external_grammar_nt} with confidence {confidence}")
                # yield rule, external_grammar_name, external_grammar_nt, confidence, None
                external = (external_grammar_name, external_grammar_nt)
                if (internal_rule.nt, external, None) not in seen_pairs:
                    seen_pairs.add((internal_rule.nt, external, None))
                    all_rule_composition_candidates.add((internal_rule, external, confidence, None))

            # FROM BASE64 MAGIC SIMILARITY
            if seeds and all(Composable.IS_MAYBE_BASE64(seed) for seed in seeds):
                log.debug(f"Rule {internal_rule.nt}.{internal_rule.id} might be base64")
                try:
                    seeds_decoded = [base64.b64decode(seed) for seed in seeds]
                except:
                    log.debug(f"Rule {internal_rule.nt}.{internal_rule.id} cannot be decoded as base64")
                else:
                    log.debug(f"Rule {internal_rule.nt}.{internal_rule.id} decoded as base64")
                    for external_grammar_name, external_grammar_nt, confidence in self.magic_similarity(seeds_decoded, token_quality_threshold):
                        log.info(f"[magic_similarity (BASE64)] Rule {internal_rule.nt}.{internal_rule.id} matches {external_grammar_name}:{external_grammar_nt} with confidence {confidence}")
                        # yield internal_rule, external_grammar_name, external_grammar_nt, confidence, "base64"
                        external = (external_grammar_name, external_grammar_nt)
                        if (internal_rule.nt, external, "base64") not in seen_pairs:
                            seen_pairs.add((internal_rule.nt, external, "base64"))
                            all_rule_composition_candidates.add((internal_rule, external, confidence, "base64"))

        ########## START UNION FIND ##########
        parent = {(internal_rule, external, encoding): (internal_rule, external, encoding) for internal_rule, external, confidence, encoding in all_rule_composition_candidates if confidence >= confidence_threshold}
        
        def find(a):
            if parent[a] != a:
                parent[a] = find(parent[a])
            return parent[a]
        
        def union(a, b):
            parent_a = find(a)
            parent_b = find(b)
            if parent_a == parent_b:
                return True
            # same encoding and same external?
            a_internal_rule, a_external, a_encoding = a
            b_internal_rule, b_external, b_encoding = b
            if a_encoding == b_encoding and a_external == b_external:
                # internals are related?
                a_slice = a_internal_rule.ancestors() | a_internal_rule.descendants() | {a_internal_rule}
                b_slice = b_internal_rule.ancestors() | b_internal_rule.descendants() | {b_internal_rule}
                if any(a_slice & b_slice):
                    parent[parent_a] = parent_b
                    return True

        # union all the rule pairs
        for a, b in itertools.combinations(parent, 2):
            union(a, b)

        # retrieve all groups
        groups = defaultdict(set)
        for a in parent:
            groups[find(a)].add(a)
        groups = [list(group) for group in groups.values()]

        if not groups:
            log.info(f"No composition candidates found")
            return
        ########## END UNION FIND ##########

        def sample_single_replacements(groups, max_samples):
            """Sample unique candidates, biased towards smaller groups"""
            # Flatten with weights
            weighted = [(c, 1/len(g)) for g in groups for c in g]
            sampled = []
            
            while weighted and len(sampled) < max_samples:
                # Sample one
                idx = random.choices(range(len(weighted)), [w for _, w in weighted])[0]
                candidate, _ = weighted.pop(idx)
                
                # Prefer START if available in same rule
                starts = [c for c, _ in weighted if c[0] == candidate[0] and c[2] == "START"]
                if starts and candidate[2] != "START":
                    candidate = random.choice(starts)
                    weighted = [(c, w) for c, w in weighted if c != candidate]
                    
                sampled.append([candidate])
            
            return sampled

        # then sample from all possible configurations
        groups = [list(group) for group in groups]
        if not groups:
            log.info(f"No composition candidates found")
            return

        total_candidates = sum(len(g) for g in groups)
        log.info(f"Sampling from {len(groups)} groups with {total_candidates} total candidates")

        for configuration in sample_single_replacements(groups, max_samples):
            yield [(internal_rule, *external, encoding) for internal_rule, external, encoding in configuration]
        log.info("Done sampling composition replacements")

    def __copy__(self):
        return Grammar._from_string(self.name, self.serialize(), tree_depth=self.tree_depth)

    def copy(self):
        return self.__copy__()

    def fuzz_wrapper(self, input_ron: bytes) -> tuple[bytes, bytes]:
        output_ron, output_bytes = self.generator.fuzz_wrapper(input_ron)
        return output_ron, output_bytes

    def helper_grammar_to_ron(self, grammar: str) -> bytes:
        return self.generator.grammar_to_ron(grammar)
    
    def mutation_wrapper(self, input_ron: bytes) -> tuple[bytes, bytes]:
        output_ron, output_bytes = self.generator.mutation_wrapper(input_ron)
        return output_ron, output_bytes
    
    def splice_mutation_wrapper(self, input_ron: bytes, other_ron: bytes) -> tuple[bytes, bytes]:
        output_ron, output_bytes = self.generator.splice_mutation_wrapper(input_ron, other_ron)
        return output_ron, output_bytes
