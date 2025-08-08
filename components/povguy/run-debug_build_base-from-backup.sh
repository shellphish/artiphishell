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

TASK_NAME=debug_build_base
PRIMARY_KEY_REPO=build_configuration

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

    # ensure that the PRIMARY_KEY exists
    if [ ! -f "${BACKUP_DIR}/${TASK_NAME}.${PRIMARY_KEY_REPO}/${PRIMARY_KEY_ID}"{,.tar.gz,.yaml} ]; then
        if [ ! -d "${BACKUP_DIR}/${TASK_NAME}.${PRIMARY_KEY_REPO}/${PRIMARY_KEY_ID}" ]; then
            echo "Invalid ${PRIMARY_KEY_REPO}: ${PRIMARY_KEY_ID}"
            exit 1
        fi
    fi
fi

# if the VDS_RECORD_ID somehow does not exist, then exit
echo "$BACKUP_DIR"
if [ ! -f "${BACKUP_DIR}/${TASK_NAME}.${PRIMARY_KEY_REPO}/${PRIMARY_KEY_ID}"{,.tar.gz,.yaml} ]; then
    if [ ! -d "${BACKUP_DIR}/${TASK_NAME}.${PRIMARY_KEY_REPO}/${PRIMARY_KEY_ID}" ]; then
        echo "Invalid ${PRIMARY_KEY_REPO}: ${PRIMARY_KEY_ID}"
        exit 1
    fi
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

export BUILD_CONFIGURATION=$(get_meta "debug_build_base.build_configuration" "$PRIMARY_KEY_ID")
export PROJECT_ID=$(lookup_meta_key "$BUILD_CONFIGURATION" ".project_id")
export OSS_FUZZ_PROJECT_DIR=$(get_fs "debug_build_base.project_oss_fuzz_repo" "$PROJECT_ID")
export CRS_TASK_META=$(get_meta "debug_build_base.crs_task" "$PROJECT_ID")
export PROJECT_NAME=$(lookup_meta_key "$CRS_TASK_META" ".project_name")
export ARCHITECTURE=$(lookup_meta_key "$BUILD_CONFIGURATION" ".architecture")
export SANITIZER=$(lookup_meta_key "$BUILD_CONFIGURATION" ".sanitizer")

if [ -z "$OUTPUT_DIR" ]; then
    export OUTPUT_DIR=$(mktemp -d)/
    echo "Created output path: $OUTPUT_DIR"
fi

export DEBUG_BUILD_BASE_ARTIFACTS="$OUTPUT_DIR/debug_build_base.debug_build_base_artifacts"
mkdir -p "$DEBUG_BUILD_BASE_ARTIFACTS"

/shellphish/povguy/run-debug_build_base.sh

echo "Created outputs: $OUTPUT_DIR"
