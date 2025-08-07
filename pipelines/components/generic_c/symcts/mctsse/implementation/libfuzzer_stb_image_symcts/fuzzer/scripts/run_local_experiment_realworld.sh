#!/bin/bash

set -x
set -euo pipefail
# if you want to use ulimit (ulimit -t <timeout>)
TIMEOUT=168h

SCRIPT_NAME=$(basename "$0")

CPU_START=$1
NUMINSTANCES=$2
TARGET_NAME=$3
shift 3
TARGET_ARGS="$@"

SESSION_NAME="${TARGET_NAME}_realworld"

SYMQEMU_PATH=~/lukas/research/mctsse/repos/symqemu/build/x86_64-linux-user/symqemu-x86_64


CORPUS_DIR=$(echo "/experiments/corpus/$TARGET_NAME")
OUTPUT_DIR=$(echo "/experiments/outputs/")
TARGET_DIR=$(echo "/experiments/targets/")

SYMCTS_BIN=$(echo "$TARGET_DIR/${TARGET_NAME}-symcts")
VANILLA_BIN=$(echo "$TARGET_DIR/${TARGET_NAME}-original")
AFL_BASE_BIN=$(echo "$TARGET_DIR/${TARGET_NAME}-afl++")
AFL_CMPLOG_BIN=$(echo "$TARGET_DIR/${TARGET_NAME}-afl++_cmplog")
AFL_LUKAS_BIN=$(echo "$TARGET_DIR/${TARGET_NAME}-afl++_lukas")

EXPERIMENT_DIR=$(echo "$OUTPUT_DIR/${TARGET_NAME}")


# try create the session before doing anything else to ensure we're not already running
tmux new-session -d -s "$SESSION_NAME"

mkdir -p "$EXPERIMENT_DIR"

echo core | sudo tee /proc/sys/kernel/core_pattern
sudo /bin/bash -c "cd /sys/devices/system/cpu; echo performance | tee cpu*/cpufreq/scaling_governor"

for f in "$EXPERIMENT_DIR"/*; do
    # if it already ends in .old, ignore
    if [[ "$f" == *.old ]]; then
        continue
    fi
    if [ -d "$f" ]; then
        # back it up to $f.YYYY-YY-YY_HH:MM:SS.old
        mv "$f" "$f.$(date +%Y-%m-%d_%H:%M:%S).old"
    fi
done

SANITIZER_ENV="ASAN_OPTIONS=abort_on_error=1,symbolize=0 UBSAN_OPTIONS=abort_on_error=1,symbolize=0"


# This is starting afl (no lukas)
function start_aflplusplus() {
    instance_name=$1
    pane_id=$2
    cpu_list=$3
    shift 3

    tmux send-keys -t "$SESSION_NAME:$instance_name.${pane_id}" "$SANITIZER_ENV AFL_NO_AFFINITY=1 AFL_SKIP_CPUFREQ=1 taskset -a --cpu-list $cpu_list timeout $TIMEOUT ../../../repos/AFLplusplus_upstream/afl-fuzz -M afl-main -i ${CORPUS_DIR} -o $EXPERIMENT_DIR/${instance_name} -m none -t 1000+ -c ${AFL_CMPLOG_BIN} $@ -- ${AFL_BASE_BIN} ${TARGET_ARGS[@]}" C-m
}

# function start_afl_cmplog() {
#     instance_name=$1
#     pane_id=$2
#     cpu_list=$3
#     shift 3

#     tmux send-keys -t "$SESSION_NAME:$instance_name.${pane_id}" "$SANITIZER_ENV AFL_NO_AFFINITY=1 AFL_SKIP_CPUFREQ=1 taskset -a --cpu-list $cpu_list timeout $TIMEOUT ../../../repos/AFLplusplus_upstream/afl-fuzz -S afl-secondary -i ${CORPUS_DIR} -o ${EXPERIMENT_DIR}/${instance_name} -m none -t 1000+ -c ${AFL_CMPLOG_BIN} $@ -- ${AFL_BASE_BIN} ${TARGET_ARGS[@]}" C-m
# }

# This is starting symcts
function start_symcts() {
    instance_name=$1
    pane_id=$2
    cpu_list=$3
    mode=$4
    shift 4

    tmux send-keys -t "$SESSION_NAME:$instance_name.${pane_id}" "$SANITIZER_ENV RUST_BACKTRACE=1 RUST_LOG=symcts_scheduler=DEBUG,INFO taskset -a --cpu-list $cpu_list timeout $TIMEOUT ./target/release/symcts -i ${CORPUS_DIR} -s $EXPERIMENT_DIR/${instance_name} -n symcts --afl-coverage-target ${AFL_LUKAS_BIN} --symqemu $SYMQEMU_PATH --symcc-target ${SYMCTS_BIN} --vanilla-target ${VANILLA_BIN} --concolic-execution-mode ${mode} -- ${TARGET_ARGS[@]}" C-m
}


NEXT_FREE_CPU=$((CPU_START))
# one per NUMINSTANCES
for i in $(seq 1 $NUMINSTANCES); do

    tmux new-window -t "$SESSION_NAME": -n "$i"
    tmux split-window -t "$SESSION_NAME:$i" -hp 50
    # tmux split-window -t "$SESSION_NAME:$i.0" -vp 50

    # Start afl++ on one core
    start_aflplusplus "$i" 0 "$NEXT_FREE_CPU"
    # start_afl_cmplog "$i" 1 "$NEXT_FREE_CPU"
    NEXT_FREE_CPU=$((NEXT_FREE_CPU + 1))


    # if $i is divisible by 2, start it with symcc mode, otherwise with symqemu mode
    if [ $((i % 2)) -eq 0 ]; then
        mode="symcc"
    else
        mode="symqemu"
    fi
    # Start symcts on one core
    start_symcts "$i" 1 "$NEXT_FREE_CPU" "$mode"
    NEXT_FREE_CPU=$((NEXT_FREE_CPU + 1))
done

tmux at -t "$SESSION_NAME"
