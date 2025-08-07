#!/bin/bash

set -eu

cd /out/

HARNESS_BIN="$1"
MINIMIZED_DIR="$2"
shift 2
CORPUS_DIRS=("$@")

"${HARNESS_BIN}" \
    "${MINIMIZED_DIR}" \
    "${CORPUS_DIRS[@]}" \
    -artifact_prefix="${MINIMIZED_DIR}/" \
    -max_len=50000 \
    -timeout=5 \
    -max_total_time=600 \
    -merge=1 \
    -merge_control_file="/tmp/merge_control_file" \
    -print_pcs=1 \
    -ignore_ooms=1 \
    -ignore_timeouts=1 \
    -ignore_crashes=1