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

TASK_NAME=debug_build
PRIMARY_KEY_REPO=target_with_sources

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

export PROJECT_ID=$PRIMARY_KEY_ID
export TARGET_WITH_SOURCES=$(get_fs "debug_build.target_with_sources" "$PROJECT_ID")

if [ -z "$OUTPUT_DIR" ]; then
    export OUTPUT_DIR=$(mktemp -d)/
    echo "Created output path: $OUTPUT_DIR"
fi

export DEBUG_BUILT_TARGET_WITH_SOURCES="$OUTPUT_DIR/debug_build.debug_built_target_with_sources"
mkdir -p "$DEBUG_BUILT_TARGET_WITH_SOURCES"

/shellphish/povguy/run-debug_build.sh

echo "Created outputs: $OUTPUT_DIR"
