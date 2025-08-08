#!/bin/bash

set -eux
TARGET_SHARED_DIR="/shared/$TASK_NAME/fuzz/${PROJECT_ID}/$JOB_ID-${REPLICA_ID:-0}/"
mkdir -p "${TARGET_SHARED_DIR}"

rsync -ra "$COVERAGE_BUILD_ARTIFACT"/ ${TARGET_SHARED_DIR}/

# AFL_SYNC_PATH="/shared/fuzzer_sync/${PROJECT_NAME}-${CP_HARNESS_NAME}-${HARNESS_INFO_ID}/sync-grammar-guy/queue"
# mkdir -p "$AFL_SYNC_PATH"
# mkdir -p "${FUZZER_SYNC_DIR}/sync-grammar-guy-${REPLICA_ID}/"

python -u /shellphish/grammar_guy/src/grammar_guy/gg/antique.py \
        -n 20 \
        --project-harness-metadata-id "${PROJECT_HARNESS_METADATA_ID}" \
        --project-metadata "${PROJECT_METADATA_FILE}" \
        -t "${TARGET_SHARED_DIR}/" \
        --project-harness-metadata "${PROJECT_HARNESS_METADATA_FILE}" \
        -idx "$FUNCTIONS_FULL_INDEX_PATH" \
        -jd "$FUNCTIONS_FULL_JSONS_DIR" \
        --target-split-metadata "${TARGET_SPLIT_METADATA}" \
        -s "$EVENTS_DIR" \