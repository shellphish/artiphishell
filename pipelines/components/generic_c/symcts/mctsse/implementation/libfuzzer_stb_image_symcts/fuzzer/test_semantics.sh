#!/bin/bash
set -x
export SYMQEMU_DIR="/home/honululu/lukas/research/mctsse/repos/symqemu/build/x86_64-linux-user/"
export PATH="$PATH:$SYMQEMU_DIR"
export LD_LIBRARY_PATH=../runtime/target/release/
INSTRUCTIONS=(divb divw divl divq idivb idivw idivl idivq)
# INSTRUCTIONS=(idivb)
TEST_SEMANTICS_DIR=~/lukas/research/mctsse/implementation/test_instruction_semantics
for INSTRUCTION in ${INSTRUCTIONS[@]}; do
    CORPUS_DIR="./corpus_test_semantics_${INSTRUCTION}/"
    rm -rf "$CORPUS_DIR"
    mkdir -p "$CORPUS_DIR"
    cp "$TEST_SEMANTICS_DIR/full_input_fuzz_${INSTRUCTION}" "$CORPUS_DIR"
    cargo run --release --features=fuzz_oneshot,no_sampling --bin symcts -- -i "$CORPUS_DIR" -- rr record -- symqemu-x86_64 "$TEST_SEMANTICS_DIR/tester_fuzz_$INSTRUCTION" | tee "results_$INSTRUCTION"
done
