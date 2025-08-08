import argparse
from pathlib import Path

from .clang_indexer import ClangIndexer
import logging

logging.basicConfig(level=logging.INFO)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--compile-args",
        type=Path,
        default=None,
        required=True,
        help="json file containing compile args for each source file",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="output location (.db file for sqlite or dir for json)",
    )
    parser.add_argument(
        "-t",
        "--threads",
        type=int,
        default=-1,
        help="amount of threads (-1 autos to 50%% of cpu threads)",
    )
    args = parser.parse_args()

    indexer = ClangIndexer(
        output=args.output,
        threads=args.threads,
        compile_args=args.compile_args,
    )
    
    indexer.run()
