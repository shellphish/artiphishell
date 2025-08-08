import pytest
from morpheus.grammar import Grammar

def tokenize(grammar_str, expect_children=None, expect_error=False):
    expect_children = expect_children or set()
    try:
        grammar = Grammar.from_string(grammar_str)
        assert grammar is not None
    except Exception as e:
        assert expect_error
    else:
        assert not expect_error
        print(expect_children == grammar.rules[0].children_nts)


class TestGrammarParsing:
    # ---- Basic Functionality Tests ----
    def test_simple_nonterminal(self):
        grammar_str = r"""
ctx.rule("START", "{TEST1}")
ctx.rule("TEST1", "test1")
        """
        tokenize(grammar_str, expect_children={"TEST1"})

    def test_simple_literal(self):
        grammar_str = r"""
ctx.rule("START", "abc")
        """
        tokenize(grammar_str, expect_children=set())

    def test_mix_literals_and_nonterminals(self):
        grammar_str = r"""
ctx.rule("START", "abc{TEST1}def")
ctx.rule("TEST1", "test1")
        """
        tokenize(grammar_str, expect_children={"TEST1"})

    def test_multiple_nonterminals(self):
        grammar_str = r"""
ctx.rule("START", "{A}{B}{C}")
ctx.rule("A", "a")
ctx.rule("B", "b")
ctx.rule("C", "c")
        """
        tokenize(grammar_str, expect_children={"A", "B", "C"})

    # ---- Escape Sequence Tests ----
    def test_escaped_curly_braces(self):
        grammar_str = r"""
ctx.rule("START", "\\{not_a_nonterminal\\}")
        """
        tokenize(grammar_str, expect_children=set())

    def test_escaped_backslash(self):
        grammar_str = r"""
ctx.rule("START", "\\\\literal_backslash")
        """
        tokenize(grammar_str, expect_children=set())

    def test_mix_escapes_and_nonterminals(self):
        grammar_str = r"""
ctx.rule("START", "\\{escaped\\}{REAL}")
ctx.rule("REAL", "real")
        """
        tokenize(grammar_str, expect_children={"REAL"})

    def test_complex_escapes(self):
        grammar_str = r"""
ctx.rule("START", "\\{\\}\\\\")
        """
        tokenize(grammar_str, expect_children=set())

    # ---- Error Cases ----
    def test_unmatched_closing_brace(self):
        grammar_str = r"""
ctx.rule("START", "abc}def")
        """
        tokenize(grammar_str, expect_error=True)

    def test_nested_opening_brace(self):
        grammar_str = r"""
ctx.rule("START", "{TEST{1}")
        """
        tokenize(grammar_str, expect_error=True)

    def test_empty_nonterminal(self):
        grammar_str = r"""
ctx.rule("START", "{}")
        """
        tokenize(grammar_str, expect_error=True)

    def test_escape_in_nonterminal(self):
        grammar_str = r"""
ctx.rule("START", "{TE\\ST}")
        """
        tokenize(grammar_str, expect_error=True)

    def test_trailing_escape(self):
        grammar_str = r"""
ctx.rule("START", "abc\\")
        """
        tokenize(grammar_str, expect_error=True)

    def test_unclosed_nonterminal(self):
        grammar_str = r"""
ctx.rule("START", "abc{TEST")
        """
        tokenize(grammar_str, expect_error=True)

    # ---- Advanced Combinations ----
    def test_adjacent_nonterminals(self):
        grammar_str = r"""
ctx.rule("START", "{A}{B}")
ctx.rule("A", "a")
ctx.rule("B", "b")
        """
        tokenize(grammar_str, expect_children={"A", "B"})

    def test_nonterminals_with_special_characters(self):
        grammar_str = r"""
ctx.rule("START", "{A_1}{B-2}")
ctx.rule("A_1", "a")
ctx.rule("B-2", "b")
        """
        tokenize(grammar_str, expect_children={"A_1", "B-2"})

    def test_complex_error_trailing_escape(self):
        grammar_str = r"""
ctx.rule("START", "{A}\\")
ctx.rule("A", "a")
        """
        tokenize(grammar_str, expect_error=True)

    def test_complex_error_empty_nonterminal(self):
        grammar_str = r"""
ctx.rule("START", "{A}{}")
ctx.rule("A", "a")
        """
        tokenize(grammar_str, expect_error=True)