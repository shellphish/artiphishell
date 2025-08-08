#!/bin/bash

set -e
set -u
set -o pipefail

source /shellphish/libs/test-utils/backup-handling-utils.sh

TASK_TYPE="${1:-}"
BACKUP_DIR="${2:-}"
PRIMARY_KEY_ID="${3:-}"
OUTPUT_DIR="${OUTPUT_DIR:-}"

export LITELLM_KEY='sk-artiphishell'
export AIXCC_LITELLM_HOSTNAME='http://wiseau.seclab.cs.ucsb.edu:666'
export PRIMARY_KEY_REPO="target_functions_jsons_dir"

if [ -z "${TASK_TYPE}" ]; then
    echo "Available tasks: full_function_index, commit_function_index"
    echo "Which task would you like to run?"
    read -r TASK_TYPE
fi

export TASK_NAME="generate_$TASK_TYPE"

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
        echo "$(basename "${f%.tar.gz}")"
    done
    echo "Which ${PRIMARY_KEY_REPO}s would you like to run?"
    read -r PRIMARY_KEY_ID

    # ensure that the VDS_RECORD_ID exists
    if [ ! -f "${BACKUP_DIR}/${TASK_NAME}.${PRIMARY_KEY_REPO}/${PRIMARY_KEY_ID}.tar.gz" ] && [ ! -d "${BACKUP_DIR}/${TASK_NAME}.${PRIMARY_KEY_REPO}/${PRIMARY_KEY_ID}" ]; then
        echo "Invalid ${PRIMARY_KEY_REPO}: ${PRIMARY_KEY_ID}"
        exit 1
    fi
fi

# if the VDS_RECORD_ID somehow does not exist, then exit
echo "$BACKUP_DIR"
if [ ! -f "${BACKUP_DIR}/${TASK_NAME}.${PRIMARY_KEY_REPO}/${PRIMARY_KEY_ID}.tar.gz" ] && [ ! -d "${BACKUP_DIR}/${TASK_NAME}.${PRIMARY_KEY_REPO}/${PRIMARY_KEY_ID}" ]; then
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


if [ ! -z "${WRITE_TO_BACKUP:-}" ]; then
    export OUTPUT_DIR="$BACKUP_DIR/"
else
    if [ -z "${OUTPUT_DIR:-}" ]; then
        export OUTPUT_DIR=$(mktemp -d)
        echo "Created output dir: $OUTPUT_DIR"
    fi
fi
if [ ! -d "$OUTPUT_DIR" ]; then
    echo "Output directory does not exist: $OUTPUT_DIR"
    exit 1
fi

echo "TASK NAME: $TASK_NAME"
echo "BACKUP DIR: $BACKUP_DIR"
echo "PRIMARY KEY ID: $PRIMARY_KEY_ID"

# Common inputs
export TARGET_FUNCTIONS_JSONS_DIR=$(get_fs "$TASK_NAME.target_functions_jsons_dir" "$PRIMARY_KEY_ID")

# Common outputs
export TARGET_FUNCTIONS_INDEX="$OUTPUT_DIR/$TASK_NAME.target_functions_index/$PRIMARY_KEY_ID"
export FUNCTIONS_BY_FILE_INDEX_JSON="$OUTPUT_DIR/$TASK_NAME.functions_by_file_index_json/$PRIMARY_KEY_ID"
mkdir -p "$(dirname "$TARGET_FUNCTIONS_INDEX")"
mkdir -p "$(dirname "$FUNCTIONS_BY_FILE_INDEX_JSON")"
if [ "$TASK_TYPE" == "full_function_index" ]; then

    echo "Creating output TARGET_FUNCTIONS_INDEX: $FUNCTIONS_BY_FILE_INDEX_JSON"
    echo "Creating output FUNCTIONS_BY_FILE_INDEX_JSON: $FUNCTIONS_BY_FILE_INDEX_JSON"
    /function-index-generator/run-full-function-index.sh

elif [ "$TASK_TYPE" == "commit_function_index" ]; then

    echo "Creating commit index in TARGET_FUNCTIONS_INDEX: $TARGET_FUNCTIONS_INDEX"
    /function-index-generator/run-commit-function-index.sh

else
    echo "Invalid TASK_TYPE: $TASK_TYPE"
fi
