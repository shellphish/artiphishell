#!/usr/bin/env python3

import argparse

from morpheus.grammar import Grammar
from morpheus.utils import log


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test loading a grammar file.")
    parser.add_argument("grammar_file", type=str, help="Path to the grammar file to load")
    args = parser.parse_args()

    # Load the grammar from the specified file
    grammar = Grammar.from_file(filepath=args.grammar_file)
    assert grammar is not None, "Failed to load unnamed grammar from file"
    log.info(f"Loaded unnamed grammar from {args.grammar_file}")
    grammar = Grammar._from_file(name="TEST", filepath=args.grammar_file)
    assert grammar is not None, "Failed to load named grammar from file"
    log.info(f"Loaded named grammar from {args.grammar_file}")
