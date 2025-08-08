# diff-ranker

Compare the function diffs (reverse diff, from child commit to parent) in the target repository 
with existing vulnerability patch diffs to rank them based on their likelihood of being security related.

See the `local_test/run_diff_rank_test.sh` to execute a Dockerized test case on Jenkins target.

The execution takes around 5 seconds for 1 modified function.

The `RETRIEVAL_API` environment variable MUST be visible to the container for this to work. 
In the local_test we define it in the Dockerfile.

See `local_tests\example_output.yaml` to see the example output format produced by `diff-ranker`, 
which is a list of yaml functions.

# Usage

```
usage: python diff_ranker.py -i DIR -d DIR -o OUTPUT [-h]

options:
  -h, --help                              show this help message and exit
  -i DIR, --clang-output-by-commit DIR    the output produces by antlr4-guy in the commit mode 
                                          for the target project

  -d DIR, --target-dir DIR                target project directory (the base directory that contains 
                                          the src/<DIR> subdirectory (e.g., <DIR>=jenkins)

  -o OUTPUT, --output-path OUTPUT         output path to write the yaml output (which contains 
                                          a list of function names
```
