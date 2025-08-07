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

EXPERIMENT_NAME="exp_generational"
tmux new-session -d -s "$EXPERIMENT_NAME"

# ["baseline", "mutations_default", "coverage_default", "scheduling_default"]
ablation_run_variant "no_generational"
ablation_run_variant "generational" --features=sage_generational_search

# 20 instances

tmux attach -t "$EXPERIMENT_NAME"