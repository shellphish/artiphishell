#!/bin/bash

set -e
set -u
set -o pipefail
set -x

source /shellphish/libs/test-utils/backup-handling-utils.sh

export LOCAL_RUN=True

BACKUP_DIR="${BACKUP_DIR:-}"

TASK_NAME=coverage_trace
PRIMARY_KEY_REPO=harness_info_id

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

set +u
if [ -z "${HARNESS_INFO_ID}" ]; then
set -u
    echo "Available HARNESS_INFO_IDs to run: "
    for f in "${BACKUP_DIR}/${TASK_NAME}.${PRIMARY_KEY_REPO}"/*; do
        echo "$(basename "${f%.yaml}")"
    done
    echo "Which HARNESS_INFO_ID would you like to run?"
    read -r HARNESS_INFO_ID

    # ensure that the HARNESS_INFO_ID exists
    if [ ! -f "${BACKUP_DIR}/${TASK_NAME}.${PRIMARY_KEY_REPO}/${HARNESS_INFO_ID}.yaml" ]; then
        echo "Invalid HARNESS_INFO_ID: ${HARNESS_INFO_ID}"
        exit 1
    fi
fi

# if the HARNESS_INFO_ID somehow does not exist, then exit
echo "$BACKUP_DIR"
if [ ! -f "${BACKUP_DIR}/${TASK_NAME}.${PRIMARY_KEY_REPO}/${HARNESS_INFO_ID}.yaml" ]; then
    echo "Invalid HARNESS_INFO_ID: ${HARNESS_INFO_ID}"
    exit 1
fi


##############################
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
##############################

HARNESS_INFO_PATH=$(get_meta ".harness_info_meta" "$HARNESS_INFO_ID")
PROJECT_ID=$(lookup_meta_key "$HARNESS_INFO_PATH" ".project_id")
TARGET_DIR=$(get_fs ".coverage_build_artifact" "$PROJECT_ID")

TARGET_DIR_NEW_FOLDER=/shared/covguy-coverage_build_artifacts
rm -rf "$TARGET_DIR_NEW_FOLDER"
cp -r "$TARGET_DIR" "$TARGET_DIR_NEW_FOLDER"

BENIGN_LOCKS_DIR=/shared/covguytests-locks-dir-benigns
rm -rf "$BENIGN_LOCKS_DIR"
mkdir -p "$BENIGN_LOCKS_DIR"

CRASH_LOCKS_DIR=/shared/covguytests-locks-dir-crashing
rm -rf "$CRASH_LOCKS_DIR"
mkdir -p "$CRASH_LOCKS_DIR"

##############################
python monitor_fast.py \
    --harness_info_id $BACKUP_DIR/coverage_trace.harness_info_id/$HARNESS_INFO_ID.yaml \
    --harness_info $BACKUP_DIR/coverage_trace.harness_info/$HARNESS_INFO_ID.yaml \
    --target_dir $TARGET_DIR_NEW_FOLDER \
    --project_metadata $BACKUP_DIR/analyze_target.metadata_path/$PROJECT_ID.yaml \
    --project_id $PROJECT_ID \
    --function_index $BACKUP_DIR/generate_full_function_index.target_functions_index/$PROJECT_ID \
    --function_index_json_dir $BACKUP_DIR/generate_full_function_index.target_functions_jsons_dir/$PROJECT_ID \
    --crashing_inputs_dir $BACKUP_DIR/coverage_trace.crashing_harness_inputs/ \
    --benign_inputs_dir $BACKUP_DIR/coverage_trace.benign_harness_inputs/ \
    --benign_inputs_dir_lock $BENIGN_LOCKS_DIR \
    --crashing_inputs_dir_lock $CRASH_LOCKS_DIR