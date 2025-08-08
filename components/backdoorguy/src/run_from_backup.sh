#!/bin/bash

source /shellphish/libs/test-utils/backup-handling-utils.sh

BACKUP_DIR="${1:-}"
PRIMARY_KEY_ID="${2:-}"

BACKUP_NAME=$(basename "$BACKUP_DIR")
export BACKUP_NAME
rm -rf /tmp/stats/*

export AIXCC_LITELLM_HOSTNAME="http://wiseau.seclab.cs.ucsb.edu:666/"
export LITELLM_KEY="sk-artiphishell-da-best!!!"
export USE_LLM_API=1

TASK_NAME=grammar_guy_fuzz
PRIMARY_KEY_REPO=harness_info

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

    # ensure that the PRIMARY_KEY exists
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

function lookup_meta_key() {
    get_metadata_key $@
}

function get_fs() {
    local key=$1
    shift 1
    get_filesystem_repo_entry "$BACKUP_DIR/${key}" $@
}

function get_meta() {
    local key=$1
    shift 1
    get_metadata_repo_entry "$BACKUP_DIR/${key}" $@
}

function get_blob() {
    local key=$1
    shift 1
    get_blob_repo_entry "$BACKUP_DIR/${key}" $@
}

export HARNESS_INFO_ID="${PRIMARY_KEY_ID}"
export HARNESS_INFO_FILE="${HARNESS_INFO_FILE:-$(get_meta grammar_guy_fuzz.harness_info_fp/ ${HARNESS_INFO_ID})}"
export PROJECT_ID=${PROJECT_ID:-$(lookup_meta_key "$HARNESS_INFO_FILE" ".project_id")}
export PROJECT_NAME=$(lookup_meta_key "$HARNESS_INFO_FILE" ".project_name")
export PROJECT_METADATA_PATH=$(get_meta "poiguy.project_metadata_path" "$PROJECT_ID")
export OSS_FUZZ_REPO_PATH=$(get_fs "pipeline_input.oss_fuzz_repo" "$PROJECT_ID")
export CRS_TASK_ANALYSIS_SOURCE=$(get_fs "kumushi.crs_tasks_analysis_source" "$PROJECT_ID")
export FUNCTIONS_INDEX=$(get_blob grammar_guy_fuzz.functions_index ${PROJECT_ID})
export TARGET_FUNCTIONS_JSONS_DIR=$(get_fs grammar_guy_fuzz.functions_jsons_dir ${PROJECT_ID})

TARGET_SHARED_FOLDER="/shared/backdoorguy/${PROJECT_ID}/"
mkdir -p $TARGET_SHARED_FOLDER || true

TEMP_DIR=$(mktemp -d -p $TARGET_SHARED_FOLDER)
export OUT_PATH="${TEMP_DIR}/out.yaml"
export LOCAL_RUN=True

./run_backdoorguy.sh
