#!/bin/bash

set -e
set -u
set -o pipefail

source /shellphish/libs/test-utils/backup-handling-utils.sh

BACKUP_DIR="${1:-}"
PRIMARY_KEY_ID="${2:-}"
OUTPUT_DIR="${OUTPUT_DIR:-}"


PRIMARY_KEY_REPO="harness_id"

TASK_NAME="aflpp_fuzz"

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

echo "TASK NAME: $TASK_NAME"
echo "BACKUP DIR: $BACKUP_DIR"
echo "PRIMARY KEY ID: $PRIMARY_KEY_ID"

export HARNESS_INFO=$(get_meta "aflpp_fuzz.harness_info" "${PRIMARY_KEY_ID}")
export TARGET_ID=$(lookup_meta_key $HARNESS_INFO ".target_id")
export TARGET_DIR=$(get_fs "aflpp_fuzz.aflpp_built_target" "${TARGET_ID}")
export CP_HARNESS_ID=$(lookup_meta_key $HARNESS_INFO ".cp_harness_id")
export CP_HARNESS_NAME=$(lookup_meta_key $HARNESS_INFO ".cp_harness_name")
export TARGET_IMAGE=$(get_meta "aflpp_fuzz.target_image" "${TARGET_ID}")
export DOCKER_IMAGE_NAME=$(lookup_meta_key $TARGET_IMAGE ".image_name")

/shellphish/aflpp/run_main_replicant.sh 2>&1 | tee -a /tmp/main.log &
sleep 10


export CMPLOG_TARGET_DIR=$(get_fs "aflpp_fuzz.cmplog_built_target" "${TARGET_ID}")
export CP_HARNESS_BINARY_PATH=$(lookup_meta_key $HARNESS_INFO ".cp_harness_binary_path")

/shellphish/aflpp/run_sub_replicant.sh 2>&1 > /tmp/rep_1.log &
/shellphish/aflpp/run_sub_replicant.sh 2>&1 > /tmp/rep_2.log &
/shellphish/aflpp/run_sub_replicant.sh 2>&1 > /tmp/rep_3.log &
/shellphish/aflpp/run_sub_replicant.sh 2>&1 > /tmp/rep_4.log &


while true; do
    sleep 10
done