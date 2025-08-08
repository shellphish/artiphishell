#!/bin/bash

set -eux
TARGET_SHARED_DIR="/shared/grammar_guy/fuzz/${PROJECT_ID}-${HARNESS_INFO_ID}"
mkdir -p "${TARGET_SHARED_DIR}"
mkdir -p /tmp/ronald

rsync -ra "$COVERAGE_BUILD_ARTIFACT"/ ${TARGET_SHARED_DIR}/

PYTHONUNBUFFERED=TRUE ipython --pdb -- /shellphish/grammar_guy/src/grammar_guy/agentic/agents/agent_assess_sarif.py \
        --harness-info-id "${HARNESS_INFO_ID}" \
        --coverage-target "${TARGET_SHARED_DIR}/" \
        --harness-info "${HARNESS_INFO_FILE}" \
        --full-functions-index "$FUNCTIONS_FULL_INDEX_PATH" \
        --full-functions-jsons "$FUNCTIONS_FULL_JSONS_DIR" \
        --sarif-report "$SARIF_REPORT"