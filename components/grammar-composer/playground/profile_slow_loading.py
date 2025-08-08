#!/usr/bin/env python3

import argparse

from morpheus.grammar import Grammar
from morpheus.utils import log

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--filepath", type=str, help="Path to the grammar file.", default="/home/ruaronicola/artiphishell/components/grammar-composer/grammars/_simplified/slow-grammar.py")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging.")
    args = parser.parse_args()

    if args.debug:
        log.setLevel("DEBUG")
    else:
        log.setLevel("INFO")
    
    old_grammar = Grammar.from_file(args.filepath)

    composition_iter = old_grammar.iter_compositions()
    set(composition_iter)