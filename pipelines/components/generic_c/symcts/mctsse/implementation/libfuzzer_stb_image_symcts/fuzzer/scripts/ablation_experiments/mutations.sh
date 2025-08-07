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

EXPERIMENT_NAME="exp_mutations"
tmux new-session -d -s "$EXPERIMENT_NAME"

ablation_run_variant "optimistic" --no-default-features --features=baseline,coverage_default,scheduling_default,optimistic_solving
ablation_run_variant "sage" --features=baseline,coverage_default,scheduling_default,sage_solving

ablation_run_variant "quicksampler" --no-default-features --features=baseline,coverage_default,scheduling_default,quicksampler_solving
ablation_run_variant "quicksampler_path_sensitive" --no-default-features --features=baseline,coverage_default,scheduling_default,quicksampler_path_sensitive_solving

ablation_run_variant "qsym" --no-default-features --features=baseline,coverage_default,scheduling_default,optimistic_solving,sage_solving
ablation_run_variant "all" --no-default-features --features=baseline,coverage_default,scheduling_default,all_mutations

# 50 instances
tmux attach -t "$EXPERIMENT_NAME"