#!/bin/bash

set -e
set -u
set -o pipefail

source /shellphish/libs/test-utils/backup-handling-utils.sh

BACKUP_DIR="${1:-}"
PRIMARY_KEY_ID="${2:-}"
OUTPUT_DIR="${OUTPUT_DIR:-}"

export LITELLM_KEY='sk-artiphishell'
export AIXCC_LITELLM_HOSTNAME='http://wiseau.seclab.cs.ucsb.edu:666'

TASK_NAME=povguy
PRIMARY_KEY_REPO=crashing_input_metadata

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

export CRASHING_INPUT_ID=$PRIMARY_KEY_ID
export CRASH_ID=$PRIMARY_KEY_ID
export CRASHING_INPUT_METADATA_PATH=$(get_meta "povguy_delta.crashing_input_metadata" "$CRASHING_INPUT_ID")
export CRASHING_INPUT_PATH=$(get_blob "povguy_delta.crashing_input_path" "$CRASHING_INPUT_ID")
export PROJECT_ID=$(lookup_meta_key "$CRASHING_INPUT_METADATA_PATH" ".project_id")
export PROJECT_METDATA_PATH=$(get_meta "povguy_delta.project_id" "$PROJECT_ID")
export TASK_TYPE=$(lookup_meta_key "$PROJECT_METDATA_PATH" ".type")
export BUILD_CONFIGURATION_ID=$(lookup_meta_key "$CRASHING_INPUT_METADATA_PATH" ".build_configuration_id")
export PROJECT_NAME=$(lookup_meta_key "$CRASHING_INPUT_METADATA_PATH" ".project_name")
# export OSS_FUZZ_REPO_PATH=$(get_fs "povguy.oss_fuzz_repo" "$PROJECT_ID")
export DEBUG_BUILD_ARTIFACTS_PATH=$(get_fs "povguy_delta.debug_build_artifacts_path" "$BUILD_CONFIGURATION_ID")
export CP_HARNESS_NAME=$(lookup_meta_key "$CRASHING_INPUT_METADATA_PATH" ".cp_harness_name")

if [ -z "$OUTPUT_DIR" ]; then
    export OUTPUT_DIR=$(mktemp -d)/
    echo "Created output path: $OUTPUT_DIR"
fi

export POV_REPORT_PATH="$OUTPUT_DIR/pov_report.yaml"
export CRASH_RUN_POV_RESULT_METADATA_PATH="$OUTPUT_DIR/crash_run_pov_result_metadata.yaml"
export REPRESENTATIVE_CRASH="$OUTPUT_DIR/representative_crash"
export REPRESENTATIVE_CRASH_METADATA="$OUTPUT_DIR/representative_crash_metadata.yaml"
export LOSAN_POV_REPORT_PATH="$OUTPUT_DIR/losan_pov_report.yaml"
export LOSAN_REPRESENTATIVE_CRASH="$OUTPUT_DIR/losan_representative_crash"
export LOSAN_REPRESENTATIVE_CRASH_METADATA="$OUTPUT_DIR/losan_representative_crash_metadata.yaml"
export BASE_PROJECT_SOURCE_PATH=$(get_fs "povguy_delta.base_project_source_path" "$BUILD_CONFIGURATION_ID")
export TASK_TYPE=$(lookup_meta_key "$PROJECT_METDATA_PATH" ".type")

/shellphish/povguy/run-povguy.sh

echo "Created outputs: $OUTPUT_DIR"