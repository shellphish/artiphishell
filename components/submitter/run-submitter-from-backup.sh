#!/bin/bash

set -ex
set -u
set -o pipefail

source /shellphish/libs/test-utils/backup-handling-utils.sh
# source ../../libs/test-utils/backup-handling-utils.sh

BACKUP_DIR="${1:-}"
PRIMARY_KEY_ID="${2:-}"
OUTPUT_DIR="${OUTPUT_DIR:-}"



TASK_NAME="submitter"
PRIMARY_KEY_REPO="crs_task"

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
    echo "Available ${PRIMARY_KEY_REPO}s to run: "
    echo "${BACKUP_DIR}/${TASK_NAME}.${PRIMARY_KEY_REPO}"
    for f in "${BACKUP_DIR}/${TASK_NAME}.${PRIMARY_KEY_REPO}"/*; do
        echo "$(basename "${f%.yaml}")"
    done
    echo "Which ${PRIMARY_KEY_REPO}s would you like to run?"
    read -r PRIMARY_KEY_ID

    # ensure that the VDS_RECORD_ID exists
    if [ ! -f "${BACKUP_DIR}/${TASK_NAME}.${PRIMARY_KEY_REPO}/${PRIMARY_KEY_ID}.yaml" ]; then
        echo "Invalid ${PRIMARY_KEY_REPO}: ${PRIMARY_KEY_ID}"
        exit 1
    fi
fi

# if the VDS_RECORD_ID somehow does not exist, then exit
echo "$BACKUP_DIR"
if [ ! -f "${BACKUP_DIR}/${TASK_NAME}.${PRIMARY_KEY_REPO}/${PRIMARY_KEY_ID}.yaml" ]; then
    echo "Invalid ${PRIMARY_KEY_REPO}: ${PRIMARY_KEY_ID}"
    exit 1
fi



function get_meta() {
    local key=$1
    shift 1
    get_metadata_repo_entry "$BACKUP_DIR/${key}" $@
}
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
function lookup_meta_key() {
    get_metadata_key $@
}

if [ -z "$OUTPUT_DIR" ]; then
    export OUTPUT_DIR=$(mktemp -d)
    echo "Created output dir: $OUTPUT_DIR"
fi

echo "TASK NAME: $TASK_NAME"
echo "BACKUP DIR: $BACKUP_DIR"
echo "PRIMARY KEY ID: $PRIMARY_KEY_ID"
export CRS_TASK=$(get_blob "submitter.crs_task" "$PRIMARY_KEY_ID.yaml")
export PATCH_DIR=${BACKUP_DIR}/${TASK_NAME}.patch_diff
export PATCH_METADATA_DIR=${BACKUP_DIR}/${TASK_NAME}.patch_diff_meta
export SARIF_DIR=${BACKUP_DIR}/${TASK_NAME}.sarif_metadata
export SARIF_RETRY_DIR=${BACKUP_DIR}/${TASK_NAME}.sarif_retry_metadata
export CRASH_DIR=${BACKUP_DIR}/${TASK_NAME}.crashing_input_path
export VULN_DIR=${BACKUP_DIR}/${TASK_NAME}.dedup_pov_report_representative_metadata_path
export VULN_METADATA_DIR=${BACKUP_DIR}/${TASK_NAME}.crashing_input_metadata_path
export SUBMITTED_VULNS=${BACKUP_DIR}/${TASK_NAME}.submitted_vulns
export SUBMITTED_PATCHES=${BACKUP_DIR}/${TASK_NAME}.submitted_patches
export SUBMITTED_SARIFS=${BACKUP_DIR}/${TASK_NAME}.submitted_sarifs
export SUBMISSIONS=${BACKUP_DIR}/${TASK_NAME}.submissions
export SUBMISSION_RESULTS_SUCCESS=${BACKUP_DIR}/${TASK_NAME}.submission_results_success
export SUBMISSION_RESULTS_FAILED=${BACKUP_DIR}/${TASK_NAME}.submission_results_failed
export DEBUG_SUBMITTER=1
export API_COMPONENTS_USE_DUMMY_DATA=1
export COMPETITION_SERVER_URL="http://localhost:8000"
export COMPETITION_SERVER_API_ID="secret"
export COMPETITION_SERVER_API_KEY="secret"

export SAVED_RESULTS="${OUTPUT_DIR}"

/app/run_submitter.sh

echo "Created output dir: $OUTPUT_DIR"
