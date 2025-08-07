# clang-indexer

Parses C/C++ source code elements and outputs the results into a sqlite database or directories of json files.

# Installation

```
pip install .
```

# Usage

```
usage: clang-indexer -r '<full/commit>' [-h] -d DIR [-o OUTPUT] [-m MODE] [-t THREADS] [-f]

options:
  -r, --run_mode        run mode: commit or full
  -h, --help            show this help message and exit
  -d DIR, --dir DIR     source code directory
  -o OUTPUT, --output OUTPUT
                        output location (.db file for sqlite or dir for json)
  -m MODE, --mode MODE  sqlite or json
  -t THREADS, --threads THREADS
                        amount of threads (-1 autos to 50% of cpu threads)
  -f, --force           force output (deletes output folder if exists)
```

---

# diff-ranker

Compare the function diffs (reverse diff, from child commit to parent) in the target repository 
with existing vulnerability patch diffs to rank them based on their likelihood of being security related.

See the `local_test/run_diff_rank_test.sh` to execute a Dockerized test case on nginx target.

The execution takes around 20 seconds for 38 modified functions.

The `RETRIEVAL_API` environment variable MUST be visible to the container for this to work. 
In the local_test we define it in the Dockerfile.

See `local_tests\example_output.yaml` to see the example output format produced by `diff-ranker`.


# Installation
```
pip install .
```


# Usage

```
usage: diff-ranker -i DIR -d DIR -o OUTPUT [-h]

options:
  -h, --help                              show this help message and exit
  -i DIR, --clang-output-by-commit DIR    the output produces by clang-indexer in the commit mode 
                                          for the target project

  -d DIR, --target-dir DIR                target project directory (the base directory that contains 
                                          the src/<DIR> subdirectory (e.g., <DIR>=nginx)

  -o OUTPUT, --output-path OUTPUT         output path to write the yaml output (which contains 
                                          a list of function names
```
