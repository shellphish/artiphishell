#!/bin/bash

set -eux
TARGET_SHARED_DIR="/shared/$TASK_NAME/fuzz/${PROJECT_ID}/$JOB_ID-${REPLICA_ID:-0}/"
mkdir -p "${TARGET_SHARED_DIR}"
mkdir -p /tmp/ronald

rsync -ra --delete "$COVERAGE_BUILD_ARTIFACT"/ ${TARGET_SHARED_DIR}/

# if $COMMIT_FUNCTIONS_INDEX is set, pass it as an extra arg
if [ "x${DELTA_MODE:-}" = "x1" ]; then
    COMMIT_FUNCTIONS_INDEX_ARG="--commit-functions-index ${COMMIT_FUNCTIONS_INDEX} --commit-functions-jsons-dir ${COMMIT_FUNCTIONS_JSONS_DIR}"
else
    COMMIT_FUNCTIONS_INDEX_ARG=""
fi

# mkdir -p "${FUZZER_SYNC_DIR}/"
PYTHONUNBUFFERED=TRUE ipython --pdb -- /shellphish/grammar_guy/src/grammar_guy/agentic/agents/agent_explorer.py \
        --project-harness-metadata-id "${PROJECT_HARNESS_METADATA_ID}" \
        --coverage-target "${TARGET_SHARED_DIR}/" \
        --project-harness-metadata "${PROJECT_HARNESS_METADATA_FILE}" \
        --project-metadata "${PROJECT_METADATA_FILE}" \
        --target-split-metadata "${TARGET_SPLIT_METADATA}" \
        --events-dir "${EVENTS_DIR}" \
        ${COMMIT_FUNCTIONS_INDEX_ARG}