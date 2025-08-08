#!/bin/bash

set -e
set -u
set -o pipefail
set -x

source /shellphish/libs/test-utils/backup-handling-utils.sh

export CORPUSGUY_SYNC_TO_FUZZER=${CORPUSGUY_SYNC_TO_FUZZER:-0}

export IS_LOCAL_RUN="1"

BACKUP_DIR="${BACKUP_DIR:-}"

TASK_NAME=corpus_inference_llm
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
export CANONICAL_BUILD_ARTIFACT=$(get_fs ".canonical_build_artifact" "$PROJECT_ID")

export ARTIPHISHELL_PROJECT_NAME=$(lookup_meta_key "$CRS_TASK_PATH" ".project_name")
export ARTIPHISHELL_PROJECT_ID=$(lookup_meta_key "$HARNESS_INFO_PATH" ".project_id")
export ARTIPHISHELL_HARNESS_NAME=$(lookup_meta_key "$HARNESS_INFO_PATH" ".cp_harness_name")


set +u
if [ -z "$OUTPUT_CORPUS_PATH" ]; then
    export OUTPUT_CORPUS_PATH=$(mktemp -d)
    echo "Created output dir: $OUTPUT_CORPUS_PATH"
fi
if [ -z "$OUTPUT_DICTIONARIES_PATH" ]; then
    export OUTPUT_DICTIONARIES_PATH=$(mktemp -d)
    echo "Created output dir: $OUTPUT_DICTIONARIES_PATH"
fi
if [ -z "$OUTPUT_GRAMMARS_PATH" ]; then
    export OUTPUT_GRAMMARS_PATH=$(mktemp -d)
    echo "Created output dir: $OUTPUT_GRAMMARS_PATH"
fi
if [ -z "$OUTPUT_METADATA_PATH" ]; then
    export OUTPUT_METADATA_PATH=$(mktemp)
    echo "Created output file: $OUTPUT_METADATA_PATH"
fi
set -u


./run_inference_llm.sh
