set -eux

export TARGET_SHARED_DIR="/shared/$TASK_NAME/${PROJECT_ID}-${JOB_ID}-${REPLICA_ID:-0}"
mkdir -p "${TARGET_SHARED_DIR}"
mkdir -p /tmp/ronald

rsync -ra --delete "$COVERAGE_BUILD_ARTIFACT"/ ${TARGET_SHARED_DIR}/

# if $COMMIT_FUNCTIONS_INDEX is set, pass it as an extra arg
if [ "${DELTA_MODE:-}" = "True" ]; then
    COMMIT_FUNCTIONS_INDEX_ARG="--commit-functions-index ${COMMIT_FUNCTIONS_INDEX}"
else
    COMMIT_FUNCTIONS_INDEX_ARG=""
fi

python -u /shellphish/grammaroomba/src/grammaroomba/run.py \
        --project-metadata "${PROJECT_METADATA_FILE}" \
        --target-shared-dir "${TARGET_SHARED_DIR}" \
        --target-split-metadata "${TARGET_SPLIT_METADATA}" \
        --project-harness-metadata-id "${PROJECT_HARNESS_METADATA_ID}" \
        --project-harness-metadata "${PROJECT_HARNESS_METADATA_FILE}" \
        --events-dir "${EVENTS_DIR}" \
        ${COMMIT_FUNCTIONS_INDEX_ARG}