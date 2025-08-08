#!/bin/bash

set -eu

cd /out/

EXTRA_LIBFUZZER_ARGS="$1"
HARNESS_BIN="$2"
CRASH_DIR="$3"
shift 3
CORPUS_DIRS=("$@")

while true; do
    "${HARNESS_BIN}" \
        "${CORPUS_DIRS[@]}" \
        ${EXTRA_LIBFUZZER_ARGS} \
        -artifact_prefix="${CRASH_DIR}/" \
        -use_value_profile=1 \
        -timeout=5 \
        -reload=1 \
        -print_pcs=1 \
        -ignore_ooms=1 \
        -ignore_timeouts=1 \
        -ignore_crashes=1
done