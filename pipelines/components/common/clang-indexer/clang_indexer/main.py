import argparse
from .indexer import ClangIndexer

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--target-dir", type=str, required=True, help="target directory")
    parser.add_argument("-r", "--run_mode", type=str, required=True, help="run mode: commit or full")
    parser.add_argument("-s", "--source-prefix", type=str, default="", help="source code prefix inside the directory")
    parser.add_argument("-o", "--output", type=str, default="result.db", help="output location (.db file for sqlite or dir for json)")
    parser.add_argument("-m", "--mode", type=str, default="sqlite", help="sqlite or json")
    parser.add_argument("-t", "--threads", type=int, default=-1, help="amount of threads (-1 autos to 50%% of cpu threads)")
    parser.add_argument("-f", "--force", action="store_true", help="force output (deletes output folder if exists)")
    parser.add_argument("--dump-cache", action="store_true", help="(just don't use this option) dump cache to /clang-indexer-cache", default=False)
    args = parser.parse_args()

    assert args.mode == "sqlite" or args.mode == "json"
    assert args.run_mode == "commit" or args.run_mode == "full"

    if args.run_mode == "commit":
        # Run the indexer in 'commit' mode, which processes the repository commit by commit.
        indexer = ClangIndexer(args.target_dir, source_prefix=args.source_prefix, output=args.output, threads=args.threads, output_mode=args.mode, force_output=args.force, dump_cache=args.dump_cache)
        indexer.run_on_commit()
    elif args.run_mode == "full":
        # Run the indexer in 'full' mode, which processes the entire repository in one go.
        indexer = ClangIndexer(args.target_dir, source_prefix=args.source_prefix, output=args.output, threads=args.threads, output_mode=args.mode, force_output=args.force, dump_cache=args.dump_cache)
        indexer.run()

