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
HARNESS_INFO_ID=$(get_primary_key "${HARNESS_INFO_ID:-}" "${BACKUP_DIR}" "snapchange_fuzz.harness_info")

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
export HARNESS_INFO=$(get_meta "snapchange_fuzz.harness_info" "$HARNESS_INFO_ID")
export SNAPSHOT_SNAPCHANGE_DIR=$(get_fs "snapchange_fuzz.snapshot_snapchange_dir" "$HARNESS_INFO_ID")
export SYZLANG_GRAMMAR_INPUT=$(get_blob "snapchange_fuzz.syzlang_grammar_input" "$HARNESS_INFO_ID")

if [ -z "$OUTPUT_DIR" ]; then
    export OUTPUT_DIR=$(mktemp -d)
    echo "Created output dir: $OUTPUT_DIR"
fi

export JOB_ID="$HARNESS_INFO_ID"
export TASK_NAME="snapchange_fuzz"
export BENIGN_INPUTS_DIR="${OUTPUT_DIR}/snapchange_fuzz.benign_harness_inputs/$JOB_ID"
export CRASHING_INPUTS_DIR="${OUTPUT_DIR}/snapchange_fuzz.crashing_harness_inputs/$JOB_ID"
export BENIGN_COVERAGE_DIR="${OUTPUT_DIR}/snapchange_fuzz.benign_coverage_dir/$JOB_ID"
export CRASH_COVERAGE_DIR="${OUTPUT_DIR}/snapchange_fuzz.crash_coverage_dir/$JOB_ID"
mkdir -p "$BENIGN_INPUTS_DIR" "$CRASHING_INPUTS_DIR" "$BENIGN_COVERAGE_DIR" "$CRASH_COVERAGE_DIR"

./run-snapchange_fuzz.sh