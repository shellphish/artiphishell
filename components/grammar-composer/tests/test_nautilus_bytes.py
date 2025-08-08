import pytest
from morpheus.grammar import Grammar


def test_bytes_rules():
    # Define grammar string with bytes rules
    grammar_str = """
ctx.rule("START", "{BYTES}")
ctx.bytes("BYTES", 0)
ctx.bytes("BYTES", 1)
ctx.bytes("BYTES", 8)
ctx.bytes("BYTES", 32)
ctx.bytes("BYTES", 2048)
ctx.bytes("BYTES", 8192)
    """
    
    # Test that the grammar is parsed correctly
    grammar = Grammar.from_string(grammar_str)
    assert grammar is not None, "Failed to parse grammar"
    
    # Generate seeds and verify variety
    seeds_sample = set(grammar.seed_iterator(nt="START", n=1000))
    assert len(seeds_sample) >= 100, f"Expected at least 100 unique seeds, got {len(seeds_sample)}"