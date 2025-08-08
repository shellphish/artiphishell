#!/bin/bash

set -e
set -u
set -o pipefail
# set -x

source /shellphish/libs/test-utils/backup-handling-utils.sh

BACKUP_DIR="${1:-}"
PROJECT_ID="${2:-}"
OUTPUT_DIR="${OUTPUT_DIR:-}"

export LITELLM_KEY='sk-artiphishell'
export AIXCC_LITELLM_HOSTNAME='http://wiseau.seclab.cs.ucsb.edu:666'

BACKUP_DIR=$(get_backup_dir "${BACKUP_DIR:-}")
PROJECT_ID=$(get_primary_key "${PROJECT_ID:-}" "${BACKUP_DIR}" "snapchange_build.project_id")

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


export PROJECT_ID="$PROJECT_ID"
export TARGET_WITH_SOURCES=$(get_fs "snapchange_build.target_with_sources" "$PROJECT_ID")
export TARGET_METADATA=$(get_meta "snapchange_build.target_metadata" "$PROJECT_ID")

export KERNEL_RELPATH=$(lookup_meta_key "$TARGET_METADATA" ".shellphish.known_sources.linux_kernel[0].relative_path")

if [ -z "$OUTPUT_DIR" ]; then
    export OUTPUT_DIR=$(mktemp -d)
    echo "Created output dir: $OUTPUT_DIR"
fi

export JOB_ID="$PROJECT_ID"
export TASK_NAME="snapchange_build"
export SNAPCHANGE_BUILT_TARGET="${OUTPUT_DIR}/snapchange_build.snapchange_built_target/$JOB_ID"
mkdir -p "$SNAPCHANGE_BUILT_TARGET"

./run-snapchange_build.sh