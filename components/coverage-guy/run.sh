#!/bin/bash

set -x
set -e
set -u


export PROJECT_ID="${PROJECT_ID}"

mkdir -p /shared/coverageguy/${PROJECT_ID}/
TARGET_SHARED_FOLDER="/shared/coverageguy/${PROJECT_ID}/"
TMPDIR=$(mktemp -d -p $TARGET_SHARED_FOLDER)

rsync -ra "$OSS_FUZZ_REPO_PATH"/ ${TMPDIR}/

ls -lh $COVERAGE_BUILD_ARTIFACT
rsync -ra $COVERAGE_BUILD_ARTIFACT/ "$TMPDIR"/projects/$PROJECT_NAME/

ls -la $TMPDIR/projects/$PROJECT_NAME/


# start monitoring
PYTHONUNBUFFERED=TRUE python3 /shellphish/coverageguy/monitor_fast.py \
     --target_dir "$TMPDIR/projects/$PROJECT_NAME/" \
     --harness_info_id "${HARNESS_INFO_ID}" \
     --harness_info "${HARNESS_INFO_PATH}" \
     --project_id "${PROJECT_ID}" \
     --project_metadata "${PROJECT_METADATA_PATH}" \
     --function_index "${FUNCTIONS_INDEX}" \
     --function_index_json_dir "${FUNCTIONS_INDEX_JSONS_DIR}" \
     --benign_inputs_dir "${BENIGN_HARNESS_INPUTS_MAIN_DIR}" \
     --benign_inputs_dir_lock "${BENIGN_HARNESS_INPUTS_LOCK_DIR}" \
     --crashing_inputs_dir "${CRASHING_HARNESS_INPUTS_MAIN_DIR}" \
     --crashing_inputs_dir_lock "${CRASHING_HARNESS_INPUTS_LOCK_DIR}"

echo "WE ARE WE HERE?!?!?"

rm -rf $TMPDIR