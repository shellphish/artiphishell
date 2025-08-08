import sys
import pytest
from pathlib import Path
from morpheus.grammar import Grammar

def helper_create_grammar_and_ron(grammar_file=Path("/tmp/test_grammar.py"), input_ron_file=None):
    grammar_str = """
ctx.rule("START", "{HECK}THIS{STUFF}")
ctx.int("HECK", 32)
ctx.bytes("STUFF", 8)
"""
    grammar_file.write_text(grammar_str)
    grammar = Grammar.from_string(grammar_str)

    if input_ron_file is not None:
        return grammar, Path(input_ron_file).read_bytes()
    else:
        return grammar, grammar.helper_grammar_to_ron(grammar_str)


def helper_create_grammar_and_two_ron(grammar_file=Path("/tmp/test_grammar.py"), input_ron_file=None, other_input_ron_file=None):
    grammar_str = """
ctx.rule("START", "{HECK}THIS{STUFF}")
ctx.int("HECK", 32)
ctx.bytes("STUFF", 8)
ctx.bytes("STUFF", 16)
"""
    grammar_file.write_text(grammar_str)
    grammar = Grammar.from_string(grammar_str)

    if input_ron_file is not None:
        input_ron = Path(input_ron_file).read_bytes()
    else:
        input_ron = grammar.helper_grammar_to_ron(grammar_str)
    
    if other_input_ron_file is not None:
        other_input_ron = Path(other_input_ron_file).read_bytes()
    else:
        other_input_ron = grammar.helper_grammar_to_ron(grammar_str)
    
    return grammar, input_ron, other_input_ron


@pytest.fixture
def grammar_and_ron(tmp_path):
    return helper_create_grammar_and_ron(grammar_file=tmp_path / "test_grammar.py")


@pytest.fixture
def grammar_and_two_ron(tmp_path):
    return helper_create_grammar_and_two_ron(grammar_file=tmp_path / "test_grammar.py")


def test_fuzz_wrapper(grammar_and_ron):
    grammar, input_ron = grammar_and_ron
    return do_fuzz_wrapper(grammar, input_ron)


def test_mut_random_copy(grammar_and_ron):
    grammar, input_ron = grammar_and_ron
    return do_mut_random_copy(grammar, input_ron)


def test_mut_random_splice(grammar_and_two_ron):
    grammar, input_ron, other_ron = grammar_and_two_ron
    return do_mut_random_splice(grammar, input_ron, other_ron)


def do_fuzz_wrapper(grammar, input_ron):
    output_ron, output_bytes = grammar.fuzz_wrapper(input_ron)
    return output_ron, output_bytes


def do_mut_random_copy(grammar, input_ron):
    output_ron, output_bytes = grammar.mutation_wrapper(input_ron)
    return output_ron, output_bytes


def do_mut_random_splice(grammar, input_ron, other_ron):
    output_ron, output_bytes = grammar.splice_mutation_wrapper(input_ron, other_ron)
    return output_ron, output_bytes


if __name__ == '__main__':
    if len(sys.argv) > 1:
        foo = helper_create_grammar_and_two_ron(input_ron_file=Path(sys.argv[1]))
    else:
        foo = helper_create_grammar_and_two_ron()
    grammar, input_ron, other_ron = foo
    print("Input RON:")
    print(input_ron)
    print("Other RON:")
    print(other_ron)
    output_ron, output_bytes = do_mut_random_splice(grammar, input_ron, other_ron)
    # output_ron, output_bytes = test_fuzz_wrapper(foo)
    # output_ron, output_bytes = do_mut_random_copy(grammar, input_ron)
    print("RON output:")
    print(output_ron)
    print("Bytes output:")
    print(output_bytes)