import sys
from pathlib import Path
from morpheus.grammar import Grammar

grammar_str = """
ctx.rule("START", "ASDF")
"""

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <grammar file>")
        sys.exit(-1)
    grammar_file = Path(sys.argv[1])
    ron_file = grammar_file.with_suffix(".ron")
    assert grammar_file.is_file(), f"File not found: {grammar_file=}"
    grammar = Grammar.from_string(grammar_str)
    ron_file.write_bytes(grammar.helper_grammar_to_ron(grammar_file.read_text()))
    print(f"Wrote RON file: {ron_file}")