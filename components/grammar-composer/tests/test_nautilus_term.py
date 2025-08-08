import pytest
from morpheus.grammar import Grammar


def test_literal_rules():
    # Define grammar string with literal rules
    grammar_str = """
ctx.rule("START", "{LITERAL}")
ctx.literal("LITERAL", b"literal")
ctx.literal("LITERAL", b"literal {with parentheses}")
ctx.literal("LITERAL", b"literal {with {nested} parentheses}")
    """
    
    # Test that the grammar is parsed correctly
    grammar = Grammar.from_string(grammar_str)
    assert grammar is not None, "Failed to parse grammar"
    
    # Generate seeds and verify they match expected literal strings
    expected = {b"literal", b"literal {with parentheses}", b"literal {with {nested} parentheses}"}
    seeds_sample = set(grammar.seed_iterator(nt="START", n=1000))
    assert seeds_sample == expected, f"Expected seeds: {expected}, got: {seeds_sample}"