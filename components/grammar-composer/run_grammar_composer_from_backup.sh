#!/bin/bash

set -e
set -u
set -o pipefail
set -x

source /shellphish/libs/test-utils/backup-handling-utils.sh

BACKUP_DIR="${BACKUP_DIR:-}"

TASK_NAME=grammar_composer_run
PRIMARY_KEY_REPO=project_harness_info

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
if [ -z "${ARTIPHISHELL_HARNESS_INFO_ID}" ]; then
set -u
    echo "Available ARTIPHISHELL_HARNESS_INFO_IDs to run: "
    for f in "${BACKUP_DIR}/${TASK_NAME}.${PRIMARY_KEY_REPO}"/*; do
        echo "$(basename "${f%.yaml}")"
    done
    echo "Which ARTIPHISHELL_HARNESS_INFO_ID would you like to run?"
    read -r ARTIPHISHELL_HARNESS_INFO_ID

    # ensure that the ARTIPHISHELL_HARNESS_INFO_ID exists
    if [ ! -f "${BACKUP_DIR}/${TASK_NAME}.${PRIMARY_KEY_REPO}/${ARTIPHISHELL_HARNESS_INFO_ID}.yaml" ]; then
        echo "Invalid ARTIPHISHELL_HARNESS_INFO_ID: ${ARTIPHISHELL_HARNESS_INFO_ID}"
        exit 1
    fi
fi

# if the ARTIPHISHELL_HARNESS_INFO_ID somehow does not exist, then exit
echo "$BACKUP_DIR"
if [ ! -f "${BACKUP_DIR}/${TASK_NAME}.${PRIMARY_KEY_REPO}/${ARTIPHISHELL_HARNESS_INFO_ID}.yaml" ]; then
    echo "Invalid ARTIPHISHELL_HARNESS_INFO_ID: ${ARTIPHISHELL_HARNESS_INFO_ID}"
    exit 1
fi



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


export ARTIPHISHELL_HARNESS_INFO_ID="$ARTIPHISHELL_HARNESS_INFO_ID"
export HARNESS_INFO_PATH=$(get_meta ".project_harness_info" "$ARTIPHISHELL_HARNESS_INFO_ID")

export PROJECT_ID=$(lookup_meta_key "$HARNESS_INFO_PATH" ".project_id")
export BUILD_CONFIGURATION_ID=$(lookup_meta_key "$HARNESS_INFO_PATH" ".build_configuration_id")

export CRS_TASK_PATH=$(get_meta ".crs_task" "$PROJECT_ID")
export PROJECT_METADATA_PATH=$(get_meta ".project_metadata" "$PROJECT_ID")
export FUNCTIONS_INDEX_PATH=$(get_fs ".functions_index" "$PROJECT_ID")
export FUNCTIONS_JSONS_DIR_PATH=$(get_fs ".functions_jsons_dir" "$PROJECT_ID")
export COVERAGE_BUILD_ARTIFACT=$(get_fs ".coverage_build_artifact" "$PROJECT_ID")

export LANGUAGE=$(lookup_meta_key "$PROJECT_METADATA_PATH" ".language")
export ARTIPHISHELL_PROJECT_NAME=$(lookup_meta_key "$CRS_TASK_PATH" ".project_name")
export ARTIPHISHELL_HARNESS_NAME=$(lookup_meta_key "$HARNESS_INFO_PATH" ".cp_harness_name")

./run_grammar_composer.sh
