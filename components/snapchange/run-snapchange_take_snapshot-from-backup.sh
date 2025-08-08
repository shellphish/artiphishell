#!/bin/bash

set -e
set -u
set -o pipefail
# set -x

source /shellphish/libs/test-utils/backup-handling-utils.sh

BACKUP_DIR="${1:-}"
HARNESS_INFO_ID="${2:-}"
OUTPUT_DIR="${OUTPUT_DIR:-}"

export LITELLM_KEY='sk-artiphishell'
export AIXCC_LITELLM_HOSTNAME='http://wiseau.seclab.cs.ucsb.edu:666'

BACKUP_DIR=$(get_backup_dir "${BACKUP_DIR:-}")
HARNESS_INFO_ID=$(get_primary_key "${HARNESS_INFO_ID:-}" "${BACKUP_DIR}" "snapchange_take_snapshot.harness_info")

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


export HARNESS_INFO_ID="$HARNESS_INFO_ID"
export HARNESS_INFO=$(get_meta "snapchange_take_snapshot.harness_info" "$HARNESS_INFO_ID")
export PROJECT_ID=$(lookup_meta_key "$HARNESS_INFO" ".project_id")
export SNAPCHANGE_BUILT_TARGET=$(get_fs "snapchange_take_snapshot.snapchange_built_target" "$PROJECT_ID")
export TARGET_METADATA=$(get_meta "snapchange_take_snapshot.target_metadata" "$PROJECT_ID")
export CP_HARNESS_ID=$(lookup_meta_key "$HARNESS_INFO" ".cp_harness_id")
export KERNEL_RELPATH=$(lookup_meta_key "$TARGET_METADATA" ".shellphish.known_sources.linux_kernel[0].relative_path")

if [ -z "$OUTPUT_DIR" ]; then
    export OUTPUT_DIR=$(mktemp -d)
    echo "Created output dir: $OUTPUT_DIR"
fi

export JOB_ID="$HARNESS_INFO_ID"
export TASK_NAME="snapchange_take_snapshot"
export SNAPSHOT_SNAPCHANGE_DIR="${OUTPUT_DIR}/snapchange_take_snapshot.snapshot_snapchange_dir/$JOB_ID"
mkdir -p "$SNAPSHOT_SNAPCHANGE_DIR"

./run-snapchange_take_snapshot.sh