#!/usr/bin/env bash
set -x

export ARTIPHISHELL_PROJECT_NAME=${ARTIPHISHELL_PROJECT_NAME}
export ARTIPHISHELL_HARNESS_NAME=${ARTIPHISHELL_HARNESS_NAME}
export ARTIPHISHELL_HARNESS_INFO_ID=${ARTIPHISHELL_HARNESS_INFO_ID}

export BENIGNS_DIR=${BENIGNS_DIR}
export CRASHES_DIR=${CRASHES_DIR}

export ARTIPHISHELL_FUZZER_SYNC_DIR="/shared/fuzzer_sync/${ARTIPHISHELL_PROJECT_NAME}-${ARTIPHISHELL_HARNESS_NAME}-${ARTIPHISHELL_HARNESS_INFO_ID}/"
mkdir -p "$ARTIPHISHELL_FUZZER_SYNC_DIR"

while true; do
    # Merge the sync dir
    merge_start_time=$(date +%s)
    /bin/bash -x /shellphish/aflpp/merge_afl_sync_dir.sh \
        ${ARTIPHISHELL_PROJECT_NAME} \
        ${ARTIPHISHELL_FUZZER_SYNC_DIR}/main/ \
        ${BENIGNS_DIR} \
        ${CRASHES_DIR}
    merge_exit_code=$?
    merge_end_time=$(date +%s)
    merge_duration=$((merge_end_time - merge_start_time))
    echo "Merge operation took $merge_duration seconds"
    if [ $merge_exit_code -ne 0 ]; then
        echo "FAILED TO MERGE PLEASE LOOK AT THIS"
    fi

    sleep 10
done