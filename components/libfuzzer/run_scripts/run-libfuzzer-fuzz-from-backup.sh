#!/bin/bash

set -eu
set -o pipefail

source /shellphish/libs/test-utils/backup-handling-utils.sh

BACKUP_DIR="${1:-}"
HARNESS_INFO_ID="${2:-}"
OUTPUT_DIR="${OUTPUT_DIR:-}"

TASK_NAME=libfuzzer_fuzz
PRIMARY_KEY_REPO=harness_info_id

if [ -z "${BACKUP_DIR}" ]; then
    num_backups=$(ls /aixcc-backups/ | wc -l)
    if [ "$num_backups" -eq 0 ]; then
        echo "No backups found in /aixcc-backups/"
        exit 1
    elif [ "$num_backups" -eq 1 ]; then
        BACKUP_NAME=$(ls /aixcc-backups/)
        echo "Only one backup found: ${BACKUP_NAME}"
    else
        echo "Available backups (in /aixcc-backups/):"
        ls /aixcc-backups/
        echo "Which backup would you like to use?"
        read -r BACKUP_NAME
        # ensure that the backup directory exists
        if [ ! -d "/aixcc-backups/${BACKUP_NAME}" ]; then
            echo "Invalid backup directory: ${BACKUP_NAME}"
            exit 1
        fi
    fi
    BACKUP_DIR="/aixcc-backups/${BACKUP_NAME}"
fi

if [ -z "${HARNESS_INFO_ID}" ]; then
    num_build_configs=$(ls "${BACKUP_DIR}/${TASK_NAME}.${PRIMARY_KEY_REPO}" | wc -l)
    if [ "$num_build_configs" -eq 0 ]; then
        echo "No build configurations found in ${BACKUP_DIR}/${TASK_NAME}.${PRIMARY_KEY_REPO}"
        exit 1
    elif [ "$num_build_configs" -eq 1 ]; then
        yaml_file=$(ls "${BACKUP_DIR}/${TASK_NAME}.${PRIMARY_KEY_REPO}")
        HARNESS_INFO_ID="${yaml_file%.yaml}"
        echo "Only one build configuration found: ${HARNESS_INFO_ID}"
    else
        echo "Available HARNESS_INFOs to run: "
        for f in "${BACKUP_DIR}/${TASK_NAME}.${PRIMARY_KEY_REPO}"/*; do
            sanitizer=$(yq '.sanitizer' "$f")
            echo "$(basename "${f%.yaml}") - ${sanitizer}"
        done
        echo "Which HARNESS_INFO would you like to run?"
        read -r HARNESS_INFO_ID
    fi

    # ensure that the HARNESS_INFO_ID exists
    if [ ! -f "${BACKUP_DIR}/${TASK_NAME}.${PRIMARY_KEY_REPO}/${HARNESS_INFO_ID}.yaml" ]; then
        echo "Invalid HARNESS_INFO_ID: ${HARNESS_INFO_ID}"
        exit 1
    fi
fi

# if the CRASHING_INPUT_ID somehow does not exist, then exit
echo "$BACKUP_DIR"
if [ ! -f "${BACKUP_DIR}/${TASK_NAME}.${PRIMARY_KEY_REPO}/${HARNESS_INFO_ID}.yaml" ]; then
    echo "Invalid HARNESS_INFO_ID: ${HARNESS_INFO_ID}"
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

export HARNESS_INFO_ID="$HARNESS_INFO_ID"
# export HARNESS_INFO=$(get_blob "libfuzzer.harness_info_id" "${HARNESS_INFO_ID}.yaml")
export HARNESS_INFO=$(get_blob "aflpp_build.harness_info_id" "${HARNESS_INFO_ID}.yaml")
export PROJECT_ID=$(lookup_meta_key "$HARNESS_INFO" ".project_id")
export CRS_PROJECT_NAME=$(lookup_meta_key "$HARNESS_INFO" ".project_name")
export OSS_FUZZ_PROJECT=$(get_fs "pipeline_input.oss_fuzz_repo" "$PROJECT_ID")

export INSTANCE_NAME="heck"
export HARNESS_NAME=$(lookup_meta_key "$HARNESS_INFO" ".cp_harness_name")
export BUILD_SANITIZER=$(lookup_meta_key "$HARNESS_INFO" ".sanitizer")
export OSS_FUZZ_PROJECT_DIR="${OSS_FUZZ_PROJECT}/projects/${CRS_PROJECT_NAME}"

/shellphish/libfuzzer/run_scripts/run-libfuzzer-fuzz.sh
echo "Created output dir: $OUTPUT_DIR"
