#!/bin/bash

source /shellphish/libs/test-utils/backup-handling-utils.sh

INVARIANTS="${INVARIANTS:-}"
BACKUP_DIR="${1:-}"
PRIMARY_KEY_ID="${2:-}"
OUTPUT_DIR="${OUTPUT_DIR:-}"
export LOCAL_RUN="${LOCAL_RUN:-1}"

echo "Using BACKUP_DIR: $BACKUP_DIR"
export LITELLM_KEY='sk-artiphishell'
export AIXCC_LITELLM_HOSTNAME='http://wiseau.seclab.cs.ucsb.edu:666'

TASK_NAME=coverage_build
PRIMARY_KEY_LINK=project_id

if [ -z "${BACKUP_DIR}" ]; then
    echo "Available backups (in /aixcc-backups/):"
    ls /aixcc-backups/
    echo "Which backup would you like to use?"
    read -r BACKUP_NAME
    # ensure that the backup directory exists
    if [ ! -d "/aixcc-backups/${BACKUP_NAME}" ]; then
        echo "Invalid backup directory: ${BACKUP_NAME}"
        exit 1
    fi
    BACKUP_DIR="/aixcc-backups/${BACKUP_NAME}"
fi

if [ -z "${PRIMARY_KEY_ID}" ]; then
    # Get the only YAML file in the directory
    file_path=$(find "${BACKUP_DIR}/${TASK_NAME}.${PRIMARY_KEY_LINK}/" -maxdepth 1 -type f -name "*.yaml" | head -n 1)
    
    if [ -z "$file_path" ]; then
        echo "No YAML file found in ${BACKUP_DIR}/${TASK_NAME}.${PRIMARY_KEY_LINK}"
        exit 1
    fi

    PRIMARY_KEY_ID=$(basename "${file_path%.yaml}")
    echo "Found PRIMARY_KEY_ID: ${PRIMARY_KEY_ID}"
fi

# if the PRIMARY_KEY_ID somehow does not exist, then exit
echo "$BACKUP_DIR"
if [ ! -f "${BACKUP_DIR}/${TASK_NAME}.${PRIMARY_KEY_LINK}/${PRIMARY_KEY_ID}.yaml" ]; then
    echo "Invalid PRIMARY_KEY_ID: ${PRIMARY_KEY_ID}"
    exit 1
fi

function get_fs() {
    local key=$1
    shift 1
    get_filesystem_repo_entry "$BACKUP_DIR/${key}" $@
}

function get_blob() {
    local key=$1
    shift 1
    get_blob_repo_entry "$BACKUP_DIR/${key}" $@
}

function get_meta() {
    local key=$1
    shift 1
    get_metadata_repo_entry "$BACKUP_DIR/${key}" $@
}

function lookup_meta_key() {
    get_metadata_key $@
}

export PROJECT_ID=$PRIMARY_KEY_ID
export PROJECT_METADATA=$(get_meta patcherq.project_metadata ${PROJECT_ID})
export COVERAGE_BUILD_ARTIFACT=$(get_fs coverage_build.coverage_build_artifacts ${PROJECT_ID})
export CRS_TASK_ANALYSIS_SOURCE=$(get_fs patcherq.crs_tasks_analysis_source ${PROJECT_ID})
export PROJECT_COMPILE_COMMAND=$(get_blob wllvm_bear_build.project_compile_commands ${PROJECT_ID})
export OUTPUT_TESTGUY_REPORT_PATH="/tmp/testguy-report-${PROJECT_ID}.yaml"

./run-testguy.sh