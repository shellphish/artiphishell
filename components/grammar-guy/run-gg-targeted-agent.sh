#!/bin/bash

set -eux
TARGET_SHARED_DIR="/shared/$TASK_NAME/fuzz/${PROJECT_ID}/$JOB_ID-${REPLICA_ID:-0}/"
mkdir -p "${TARGET_SHARED_DIR}"
mkdir -p /tmp/ronald

rsync -ra "$COVERAGE_BUILD_ARTIFACT"/ ${TARGET_SHARED_DIR}/

PYTHONUNBUFFERED=TRUE ipython --pdb -- /shellphish/grammar_guy/src/grammar_guy/agentic/agents/agent_reach_function.py \
        --harness-info-id "${HARNESS_INFO_ID}" \
        --coverage-target "${TARGET_SHARED_DIR}/" \
        --harness-info "${HARNESS_INFO_FILE}" \
        --full-functions-index "$FUNCTIONS_FULL_INDEX_PATH" \
        --full-functions-jsons "$FUNCTIONS_FULL_JSONS_DIR"