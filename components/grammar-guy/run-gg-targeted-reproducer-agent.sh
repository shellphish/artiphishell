#!/bin/bash

set -eux

COVERAGE_TARGET_SHARED_DIR="/shared/grammar_guy/fuzz/${PROJECT_ID}-${HARNESS_INFO_ID}/coverage/"
LOSAN_TARGET_SHARED_DIR="/shared/grammar_guy/fuzz/${PROJECT_ID}-${HARNESS_INFO_ID}/debug/"
mkdir -p "${COVERAGE_TARGET_SHARED_DIR}" "${LOSAN_TARGET_SHARED_DIR}"


rsync -ra "$COVERAGE_BUILD_ARTIFACT"/ ${COVERAGE_TARGET_SHARED_DIR}/
rsync -ra "$LOSAN_BUILD_ARTIFACT_PATH"/ ${LOSAN_TARGET_SHARED_DIR}/

mkdir -p "$FUZZER_SYNC_DIR/"
PYTHONUNBUFFERED=TRUE ipython --pdb -- /shellphish/grammar_guy/src/grammar_guy/agentic/agents/agent_reproduce_losan_crash.py \
    --representative-crashing-metadata-id  "$LOSAN_DEDUP_POV_REPORT_REPRESENTATIVE_CRASHING_INPUT_ID" \
    --representative-crashing-metadata  "$LOSAN_DEDUP_POV_REPORT_REPRESENTATIVE_CRASHING_INPUT_METADATA_FILE" \
    --harness-info "${HARNESS_INFO_FILE}" \
    --harness-info-id "${HARNESS_INFO_ID}" \
    --coverage-target "${COVERAGE_TARGET_SHARED_DIR}/" \
    --losan-target "${LOSAN_TARGET_SHARED_DIR}/" \
    --fuzzer-sync-dir "$FUZZER_SYNC_DIR/sync-grammar-agent-reproduce-losan-${REPLICA_ID}/"
