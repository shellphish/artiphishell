#!/bin/bash
# function print_first_and_last_csv_line() {
#     python -c "lines = open('/dev/stdin', 'r').read().strip().split('\n'); print('\n'.join(lines[:1] + lines[-1:]))"
# }
# set -x
for f in experiment_cmplog/local_experiment_sync_*;
do
    echo "$f"
    echo -n "symcts     "; ./target/release/cov_over_time "$f/symcts_latest/corpus" -- ./harness_symcts_afl++ 2>/dev/null | tail -n 1 || echo
    echo -n "afl-main   "; ./target/release/cov_over_time "$f/afl-main/queue" -- ./harness_symcts_afl++ 2>/dev/null | tail -n 1 || echo
    echo -n "afl-cmplog "; ./target/release/cov_over_time "$f/afl-secondary/queue" -- ./harness_symcts_afl++ 2>/dev/null | tail -n 1 || echo
    echo
done
for f in experiment_no_cmplog/local_experiment_sync_*;
do
    echo "$f"
    echo -n "symcts     "; ./target/release/cov_over_time "$f/symcts_latest/corpus" -- ./harness_symcts_afl++ 2>/dev/null | tail -n 1 || echo
    echo -n "afl-main   "; ./target/release/cov_over_time "$f/afl-main/queue" -- ./harness_symcts_afl++ 2>/dev/null | tail -n 1 || echo
    echo -n "afl-cmplog "; ./target/release/cov_over_time "$f/afl-secondary/queue" -- ./harness_symcts_afl++ 2>/dev/null | tail -n 1 || echo
    echo
done
