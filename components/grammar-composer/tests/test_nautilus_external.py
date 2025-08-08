import pytest
import tempfile
from morpheus.grammar import Grammar


@pytest.fixture
def temp_grammar_files():
    with tempfile.NamedTemporaryFile() as f1, tempfile.NamedTemporaryFile() as f2:
        nested_external_bbbb_grammar_str = """
ctx.rule("START", "{BBBB}")
ctx.rule("BBBB", "BBBB")
"""
        f1.write(nested_external_bbbb_grammar_str.encode())
        f1.flush()

        external_aaaa_grammar_str = f"""
ctx.rule("START", "{{AAAA}}")
ctx.rule("START", "{{BBBB}}")
ctx.rule("AAAA", "AAAA")
ctx.external("BBBB", "BBBB_GRAMMAR", "BBBB", "{f1.name}")
"""
        f2.write(external_aaaa_grammar_str.encode())
        f2.flush()
        
        yield f1, f2


@pytest.fixture
def temp_recursive_grammar_files():
    with tempfile.NamedTemporaryFile() as f1:
        recursive_external_aaaa_grammar_str = """
ctx.rule("START", "{RECURSIVEAAAA}")
ctx.external("RECURSIVEAAAA", "AAAA_GRAMMAR", "RULEAAAA", "{f1.name}")
ctx.rule("RULEAAAA", "AAAA")
"""
        f1.write(recursive_external_aaaa_grammar_str.encode())
        f1.flush()
        
        yield f1


class TestExternalRulesWithCustomPath:
    def test_external_import_at_start_without_nesting(self, temp_grammar_files):
        f1, _ = temp_grammar_files
        grammar_str = f"""
ctx.rule("START", "{{BBBB}}")
ctx.external("BBBB", "BBBB_GRAMMAR", "START", "{f1.name}")
"""
        grammar = Grammar.from_string(grammar_str)
        seeds_sample = set(grammar.seed_iterator(nt="START", n=100))
        assert seeds_sample == {b"BBBB"}

    def test_external_import_at_nonterminal_without_nesting(self, temp_grammar_files):
        f1, _ = temp_grammar_files
        grammar_str = f"""
ctx.rule("START", "{{BBBB}}")
ctx.external("BBBB", "BBBB_GRAMMAR", "BBBB", "{f1.name}")
"""
        grammar = Grammar.from_string(grammar_str)
        seeds_sample = set(grammar.seed_iterator(nt="START", n=100))
        assert seeds_sample == {b"BBBB"}

    def test_external_import_at_start_with_nesting(self, temp_grammar_files):
        _, f2 = temp_grammar_files
        grammar_str = f"""
ctx.rule("START", "{{AAAA}}")
ctx.external("AAAA", "AAAA_GRAMMAR", "START", "{f2.name}")
"""
        grammar = Grammar.from_string(grammar_str)
        seeds_sample = set(grammar.seed_iterator(nt="START", n=100))
        assert seeds_sample == {b"AAAA", b"BBBB"}

    def test_external_import_at_nonterminal_with_nesting(self, temp_grammar_files):
        _, f2 = temp_grammar_files
        grammar_str = f"""
ctx.rule("START", "{{AAAA}}")
ctx.external("AAAA", "AAAA_GRAMMAR", "BBBB", "{f2.name}")
"""
        grammar = Grammar.from_string(grammar_str)
        seeds_sample = set(grammar.seed_iterator(nt="START", n=100))
        assert seeds_sample == {b"BBBB"}


class TestRecursiveExternalRules:
    def test_self_recursion_from_root_grammar(self, temp_recursive_grammar_files):
        f1 = temp_recursive_grammar_files
        grammar_str = f"""
ctx.rule("START", "{{RECURSIVEAAAA}}")
ctx.external("RECURSIVEAAAA", "AAAA_GRAMMAR", "RULEAAAA", "{f1.name}")
ctx.rule("RULEAAAA", "AAAA")
"""
        grammar = Grammar.from_string(grammar_str)
        seeds_sample = set(grammar.seed_iterator(nt="START", n=100))
        assert seeds_sample == {b"AAAA"}

    def test_self_recursion_from_external_grammar(self, temp_recursive_grammar_files):
        f1 = temp_recursive_grammar_files
        grammar_str = f"""ctx.external("START", "AAAA_GRAMMAR", "START", "{f1.name}")"""
        grammar = Grammar.from_string(grammar_str)
        seeds_sample = set(grammar.seed_iterator(nt="START", n=100))
        assert seeds_sample == {b"AAAA"}


class TestExternalRulesWithReferenceGrammar:
    def test_reference_grammar_parsing(self):
        grammar_str = """
ctx.rule("START", "{EXTERNAL}")
ctx.external("EXTERNAL", "PNG")
"""
        
        grammar = Grammar.from_string(grammar_str)
        assert grammar is not None, "Failed to parse grammar"
    
    def test_reference_grammar_imports(self):
        grammar_str = """
ctx.rule("START", "{EXTERNAL}")
ctx.external("EXTERNAL", "PNG")
"""
        grammar = Grammar.from_string(grammar_str)
        png_reference_grammar = Grammar._from_file("PNG", "/shellphish/libs/nautilus/grammars/reference/PNG.py")
        
        external_rules = {r for r in grammar.rules if ":" in r.nt}
        other_rules = {r for r in grammar.rules if r.nt not in external_rules}
        
        assert {r.nt for r in external_rules} == {r.nt for r in png_reference_grammar.rules}-{"ANYRULE"}
        assert {r.nt for r in grammar.rules}-{r.nt for r in external_rules}-{"ANYRULE"} == {"START", "EXTERNAL"}
    
    def test_reference_grammar_generation_consistency(self):
        grammar_str = """
ctx.rule("START", "{EXTERNAL}")
ctx.external("EXTERNAL", "PNG")
"""
        grammar = Grammar.from_string(grammar_str)
        png_reference_grammar = Grammar._from_file("PNG", "/shellphish/libs/nautilus/grammars/reference/PNG.py")
        
        for nt in grammar.nts:
            if all(r.is_literal() for r in grammar.nt_to_rules[nt]):
                reference_generations = set(png_reference_grammar.seed_iterator(nt=nt))
                generations = set(grammar.seed_iterator(nt=nt))
                assert generations == reference_generations