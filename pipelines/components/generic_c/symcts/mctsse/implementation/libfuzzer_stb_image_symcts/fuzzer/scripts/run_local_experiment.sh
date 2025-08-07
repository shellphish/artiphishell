#!/bin/bash


TIMEOUT=48h
SCRIPT_NAME=$(basename "$0")

EXPERIMENT_NAME=$1
EXPERIMENT_DIR=$1
rm -ri "$EXPERIMENT_DIR"
mkdir -p "$EXPERIMENT_DIR"

echo core | sudo tee /proc/sys/kernel/core_pattern
sudo /bin/bash -c "cd /sys/devices/system/cpu; echo performance | tee cpu*/cpufreq/scaling_governor"

for f in ./local_experiment_sync_*; do
    # if it already ends in .old, ignore
    if [[ "$f" == *.old ]]; then
        continue
    fi
    if [ -d "$f" ]; then
        rm -rf "$f.old"
        mv "$f" "$f.old"
    fi
done

function start_afl() {
    window_name=$1
    cpu_list=$2
    shift 2
    tmux send-keys -t "$SESSION_NAME:$window_name" "AFL_NO_AFFINITY=1 AFL_SKIP_CPUFREQ=1 taskset -a --cpu-list $cpu_list timeout $TIMEOUT ../../../repos/AFLplusplus_upstream/afl-fuzz -M afl-main -i corpus -o $EXPERIMENT_DIR/local_experiment_sync_${EXPERIMENT_NAME} -m none -t 1000+ $@ -- ./harness_afl++" C-m
}
function start_afl_cmplog() {
    window_name=$1
    cpu_list=$2
    shift 2
    # tmux send-keys -t "$SESSION_NAME:$window_name" "AFL_NO_AFFINITY=1 AFL_SKIP_CPUFREQ=1 taskset -a --cpu-list $cpu_list timeout $TIMEOUT ../../../repos/AFLplusplus_upstream/afl-fuzz -S afl-secondary -i corpus -o $EXPERIMENT_DIR/local_experiment_sync_${EXPERIMENT_NAME} -m none -t 1000+ -c ./harness_afl++.cmplog $@ -- ./harness_afl++" C-m
}
function start_symcc_helper() {
    window_name=$1
    cpu_list=$2
    shift 2
    tmux send-keys -t "$SESSION_NAME:$window_name" "LD_LIBRARY_PATH=/home/Lukas-Dresel/lukas/research/mctsse/repos/symcc/build_qsym/SymRuntime-prefix/src/SymRuntime-build/ RUST_LOG=debug taskset -a --cpu-list $cpu_list timeout $TIMEOUT symcc_fuzzing_helper -v -a afl-main -n symcc -o $EXPERIMENT_DIR/local_experiment_sync_${EXPERIMENT_NAME} -- ./target_symcc" C-m
}
function start_symcts() {
    window_name=$1
    cpu_list=$2
    shift 2

    tmux send-keys -t "$SESSION_NAME:$window_name" "RUST_LOG=symcts_scheduler=DEBUG,generate_mutations_sampled=INFO,sync_from_afl_stage=INFO taskset -a --cpu-list $cpu_list timeout $TIMEOUT ./target/release/symcts -i corpus -s $EXPERIMENT_DIR/local_experiment_sync_${EXPERIMENT_NAME} -c ./harness_symcts_afl++ -n symcts -- ./target_symcts" C-m
}

set -x
SESSION_NAME="local_experiment_${EXPERIMENT_NAME}_$(date +%s)"
tmux new-session -d -s "$SESSION_NAME"

NEXT_FREE_CPU=48
NUMINSTANCES=5

# one per NUMINSTANCES
for i in $(seq 1 $NUMINSTANCES); do
    export EXPERIMENT_NAME="afl_${i}"
    EXPERIMENT_NAME="$EXPERIMENT_NAME"

    tmux new-window -t "$SESSION_NAME": -n "$EXPERIMENT_NAME"
    start_afl "$EXPERIMENT_NAME.0" "$NEXT_FREE_CPU"
    
    tmux split-window -t "$SESSION_NAME:$EXPERIMENT_NAME" -vp 50
    start_afl_cmplog "$EXPERIMENT_NAME.1" "$NEXT_FREE_CPU"

    NEXT_FREE_CPU=$((NEXT_FREE_CPU + 2))
done

for i in $(seq 1 $NUMINSTANCES); do
    export EXPERIMENT_NAME="symcc_afl_${i}"
    EXPERIMENT_NAME="$EXPERIMENT_NAME"

    tmux new-window -t "$SESSION_NAME": -n "$EXPERIMENT_NAME"
    tmux split-window -t "$SESSION_NAME:$EXPERIMENT_NAME.0" -hp 45
    tmux split-window -t "$SESSION_NAME:$EXPERIMENT_NAME.0" -vp 50

    # 0 == original pane, afl-main
    # 1 == afl-secondary
    # 2 == symcc

    start_afl "$EXPERIMENT_NAME.0" "$NEXT_FREE_CPU" "-F $EXPERIMENT_DIR/local_experiment_sync_${EXPERIMENT_NAME}/symcc/queue"
    start_afl_cmplog "$EXPERIMENT_NAME.1" "$NEXT_FREE_CPU"
    
    while [ ! -d "$EXPERIMENT_DIR/local_experiment_sync_${EXPERIMENT_NAME}" ]; do
        sleep 1
    done
    start_symcc_helper "$EXPERIMENT_NAME.2" "$NEXT_FREE_CPU"

    NEXT_FREE_CPU=$((NEXT_FREE_CPU + 2))
done

for i in $(seq 1 $NUMINSTANCES); do
    export EXPERIMENT_NAME="symcts_afl_${i}"
    EXPERIMENT_NAME="$EXPERIMENT_NAME"
    
    tmux new-window -t "$SESSION_NAME": -n "$EXPERIMENT_NAME"
    tmux split-window -t "$SESSION_NAME:$EXPERIMENT_NAME.0" -hp 45
    tmux split-window -t "$SESSION_NAME:$EXPERIMENT_NAME.0" -vp 50

    # 0 == original pane, afl-main
    # 1 == afl-secondary
    # 2 == symcts

    start_afl "$EXPERIMENT_NAME.0" "$NEXT_FREE_CPU" "-F $EXPERIMENT_DIR/local_experiment_sync_${EXPERIMENT_NAME}/symcts/corpus"
    start_afl_cmplog "$EXPERIMENT_NAME.1" "$NEXT_FREE_CPU"
    start_symcts "$EXPERIMENT_NAME.2" "$NEXT_FREE_CPU"

    NEXT_FREE_CPU=$((NEXT_FREE_CPU + 2))
done

for i in $(seq 1 $NUMINSTANCES); do
    export EXPERIMENT_NAME="symcts_${i}"
    EXPERIMENT_NAME="$EXPERIMENT_NAME"

    tmux new-window -t "$SESSION_NAME": -n "$EXPERIMENT_NAME"
    start_symcts "$EXPERIMENT_NAME" "$NEXT_FREE_CPU"

    NEXT_FREE_CPU=$((NEXT_FREE_CPU + 2))
done

tmux at
