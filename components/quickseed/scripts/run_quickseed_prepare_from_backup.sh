#!/bin/bash

set -e
set -u
set -o pipefail
set -x

source /shellphish/libs/test-utils/backup-handling-utils.sh

BACKUP_DIR="${1:-}"
PROJECT_ID="${2:-}"

TASK_NAME=quick_seed_prepare

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
PRIMARY_KEY_REPO=project_id

echo "$BACKUP_DIR"
if [ -z "${PROJECT_ID}" ]; then
    echo "Available Project Info to run: "
    for f in "${BACKUP_DIR}/${TASK_NAME}.${PRIMARY_KEY_REPO}"/*; do
        echo "$(basename "${f%.yaml}")"
    done
    echo "Which PROJECT_ID would you like to run?"
    read -r PROJECT_ID
fi

export PROJECT_ID="${PROJECT_ID}"

function get_meta() {
    local key=$1
    shift 1
    get_metadata_repo_entry "$BACKUP_DIR/${TASK_NAME}${key}" $@
}

function get_fs() {
    local key=$1
    shift 1
    get_filesystem_repo_entry "$BACKUP_DIR/${TASK_NAME}${key}" $@
}
function get_blob() {
    local key=$1
    shift 1
    get_blob_repo_entry "$BACKUP_DIR/${TASK_NAME}${key}" $@
}
function lookup_meta_key() {
    get_metadata_key $@
}



export HARNESS_INFO="$BACKUP_DIR/${TASK_NAME}.harness_infos/"

export HARNESS_METADATA=$(get_meta ".harness_metadata_path" "$PROJECT_ID")
export AGGREGATED_HARNESS_INFO=$(mktemp -d /tmp/aggregated_harness_info.XXXXXX)
export AGGREGATED_HARNESS_INFO=$AGGREGATED_HARNESS_INFO/aggregated_harness_info.yaml

/quickseed/scripts/prepare_quickseed.sh