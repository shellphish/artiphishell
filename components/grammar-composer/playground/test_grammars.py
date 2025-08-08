#!/usr/bin/env python

import argparse
import glob
import itertools
import os
import time

from collections import defaultdict

from morpheus.grammar import Grammar
from morpheus.utils import log


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("path", type=str)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    # assert os.path.exists(args.path), f"Path does not exist: {args.path}"

    if args.debug:
        log.setLevel("DEBUG")
    else:
        log.setLevel("INFO")

    def hydrate_grammar(old_grammar):
        composition_iter = old_grammar.iter_compositions()
        for new_grammar in itertools.islice(composition_iter, 10):
            pass
    
    seen_in_dir = defaultdict(int)
    def filter_top_n_per_dir(iterator, n=1):
        for filepath in iterator:
            dirname = os.path.dirname(filepath)
            if seen_in_dir[dirname] >= n:
                continue
            seen_in_dir[dirname] += 1
            yield filepath

    if os.path.isfile(args.path):
        log.info("\n" + "=" * 80 + f"\nHydrating grammar from {args.path}\n" + "=" * 80 + "\n")
        old_grammar = Grammar.from_file(args.path)
        hydrate_grammar(old_grammar)
    else:
        grammar_filepaths = set([f for f in glob.glob(args.path, recursive=True) if os.path.isfile(f)])
        if args.limit:
            grammar_filepaths = set(filter_top_n_per_dir(grammar_filepaths, args.limit))
        log.info(f"Found {len(grammar_filepaths)} files to hydrate")
        for i, filepath in enumerate(grammar_filepaths):
            start_time = time.time()
            log.info("\n" + "=" * 80 + f"\nHydrating grammar ({i+1}/{len(grammar_filepaths)}) from {filepath}\n" + "=" * 80 + "\n")
            old_grammar = Grammar.from_file(filepath)
            hydrate_grammar(old_grammar)
            log.info(f"Hydrated grammar in {time.time() - start_time:.2f}s")
