import pytest
from morpheus.grammar import Grammar


def test_int_rules():
    # Define grammar string with int rules
    grammar_str = """
ctx.rule("START", "{INT}")
ctx.int("INT", 0)
ctx.int("INT", 1)
ctx.int("INT", 8)
ctx.int("INT", 32)
# ctx.int("INT", 2048)
# ctx.int("INT", 8192)
    """
    
    # Test that the grammar is parsed correctly
    grammar = Grammar.from_string(grammar_str)
    assert grammar is not None, "Failed to parse grammar"
    
    # Generate seeds and verify variety
    seeds_sample = set(grammar.seed_iterator(nt="START", n=1000))
    assert len(seeds_sample) >= 100, f"Expected at least 100 unique seeds, got {len(seeds_sample)}"