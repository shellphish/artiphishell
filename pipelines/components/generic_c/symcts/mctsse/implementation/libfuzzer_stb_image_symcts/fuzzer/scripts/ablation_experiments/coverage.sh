#!/bin/bash -e

##
# Pre-requirements:
# - env FUZZER: fuzzer name (from fuzzers/)
# - env TARGET: target name (from targets/)
# + env MAGMA: path to magma root (default: ../../)
# + env ISAN: if set, build the benchmark with ISAN/fatal canaries (default:
#       unset)
# + env HARDEN: if set, build the benchmark with hardened canaries (default:
#       unset)
##
set -x

SCRIPT_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}")" && pwd )
source "$SCRIPT_DIR/BASE.sh"

# build all targets for all fuzzers in a new tmux session with one per window each

EXPERIMENT_NAME="exp_coverage"
tmux new-session -d -s "$EXPERIMENT_NAME"

# ["baseline", "mutations_default", "coverage_default", "scheduling_default"]
ablation_run_variant "no_bucketing" --no-default-features --features=baseline,mutations_default,scheduling_default
ablation_run_variant "no_bucketing_context_sensitive" --no-default-features --features=baseline,mutations_default,scheduling_default,coverage_context_sensitive

ablation_run_variant "bucketing_afl" --no-default-features --features=baseline,mutations_default,scheduling_default,coverage_loop_bucketing_afl
ablation_run_variant "bucketing_afl_context_sensitive" --no-default-features --features=baseline,mutations_default,scheduling_default,coverage_loop_bucketing_afl,coverage_context_sensitive

ablation_run_variant "bucketing_symcts" --no-default-features --features=baseline,mutations_default,scheduling_default,coverage_loop_bucketing_symcts
ablation_run_variant "bucketing_symcts_context_sensitive" --no-default-features --features=baseline,mutations_default,scheduling_default,coverage_loop_bucketing_symcts,coverage_context_sensitive

# 60 instances

tmux attach -t "$EXPERIMENT_NAME"