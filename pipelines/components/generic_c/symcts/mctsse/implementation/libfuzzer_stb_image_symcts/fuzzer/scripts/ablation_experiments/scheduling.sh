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

EXPERIMENT_NAME="exp_scheduling"
tmux new-session -d -s "$EXPERIMENT_NAME"

# ["baseline", "mutations_default", "coverage_default", "scheduling_default"]
ablation_run_variant "uniform_random__sampling" --no-default-features --no-default-features --features=baseline,mutations_default,coverage_default,scheduling_uniform_random,scheduling_weight_function_sampling_counts
ablation_run_variant "uniform_random__unmutated" --no-default-features --no-default-features --features=baseline,mutations_default,coverage_default,scheduling_uniform_random,scheduling_weight_function_least_unmutated

ablation_run_variant "weighted_random__sampling" --no-default-features --features=baseline,mutations_default,coverage_default,scheduling_weighted_random,scheduling_weight_function_sampling_counts
ablation_run_variant "weighted_random__unmutated" --no-default-features --features=baseline,mutations_default,coverage_default,scheduling_weighted_random,scheduling_weight_function_least_unmutated

ablation_run_variant "weighted_minimum__sampling" --no-default-features --features=baseline,mutations_default,coverage_default,scheduling_weighted_minimum,scheduling_weight_function_sampling_counts
ablation_run_variant "weighted_minimum__unmutated" --no-default-features --features=baseline,mutations_default,coverage_default,scheduling_weighted_minimum,scheduling_weight_function_least_unmutated

# 60 instances
tmux attach -t "$EXPERIMENT_NAME"