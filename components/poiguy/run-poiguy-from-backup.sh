#!/bin/bash

set -e
set -u
set -o pipefail

source /shellphish/libs/test-utils/backup-handling-utils.sh

BACKUP_DIR="${1:-}"
PRIMARY_KEY_ID="${2:-}"
POI_REPORTS_DIR="${POI_REPORTS_DIR:-}"

export LITELLM_KEY='sk-artiphishell'
export AIXCC_LITELLM_HOSTNAME='http://wiseau.seclab.cs.ucsb.edu:666'

TASK_NAME=poiguy
PRIMARY_KEY_REPO=pov_report_path

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
    for f in "${BACKUP_DIR}/${TASK_NAME}.${PRIMARY_KEY_REPO}"/*; do
        echo "$(basename "${f%.yaml}")"
    done
    echo "Which ${PRIMARY_KEY_REPO}s would you like to run?"
    read -r PRIMARY_KEY_ID

    # ensure that the VDS_RECORD_ID exists
    if [ ! -f "${BACKUP_DIR}/${TASK_NAME}.${PRIMARY_KEY_REPO}/${PRIMARY_KEY_ID}" ]; then
        echo "Invalid ${PRIMARY_KEY_REPO}: ${PRIMARY_KEY_ID}"
        exit 1
    fi
fi

# if the VDS_RECORD_ID somehow does not exist, then exit
echo "$BACKUP_DIR"
if [ ! -f "${BACKUP_DIR}/${TASK_NAME}.${PRIMARY_KEY_REPO}/${PRIMARY_KEY_ID}" ]; then
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

if [ -z "$POI_REPORTS_DIR" ]; then
    export POI_REPORTS_DIR=$(mktemp -d)/poi.yaml
    echo "Created output dir: $POI_REPORTS_DIR"
fi

echo "TASK NAME: $TASK_NAME"
echo "BACKUP DIR: $BACKUP_DIR"
echo "PRIMARY KEY ID: $PRIMARY_KEY_ID"

export REPORT_ID="$PRIMARY_KEY_ID"
export POV_REPORT_ID="$REPORT_ID"
export POV_REPORT_PATH=$(get_blob "poiguy.pov_report_path" "$REPORT_ID")
export PROJECT_ID=$(lookup_meta_key "$POV_REPORT_PATH" ".project_id")
export PROJECT_METADATA_PATH=$(get_meta "poiguy.project_metadata_path" "$PROJECT_ID")
export FULL_FUNCTIONS_BY_FILE_INDEX_PATH=$(get_blob "generate_full_function_index.functions_by_file_index_json" "$PROJECT_ID")
/poiguy/run-poiguy.sh

echo "Created output dir: $POI_REPORTS_DIR"
