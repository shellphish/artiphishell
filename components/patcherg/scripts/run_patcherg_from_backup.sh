#!/bin/bash

set -e
set -u
set -o pipefail
set -x

source /shellphish/libs/test-utils/backup-handling-utils.sh

export GITHUB_CREDS_PATH="/root/.git-credentials"
DISPATCH="${1:-}"
BACKUP_DIR="${2:-}"
PRIMARY_KEY_ID="${3:-}"


export LITELLM_KEY='sk-artiphishell'
export AIXCC_LITELLM_HOSTNAME='http://wiseau.seclab.cs.ucsb.edu:666'

PATCHERG_TASK_NAME=patcherg
PRIMARY_KEY_REPO=crs_task

if [ -z "${DISPATCH}" ]; then
    echo "Dispatch mode"
    read -r DISPATCH
fi

if [ "${DISPATCH}" -eq 0 ]; then
    echo "If ${DISPATCH} is 0 then it will run in dispatch mode,"
    export DISPATCH=1
else
    echo "run in guard mode"
    export GUARD=1
fi


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
    for f in "${BACKUP_DIR}/${PATCHERG_TASK_NAME}.${PRIMARY_KEY_REPO}"/*; do
        echo "$(basename "${f%.yaml}")"
    done
    echo "Which ${PRIMARY_KEY_REPO}s would you like to run?"
    read -r PRIMARY_KEY_ID

    # ensure that the VDS_RECORD_ID exists
    if [ ! -f "${BACKUP_DIR}/${PATCHERG_TASK_NAME}.${PRIMARY_KEY_REPO}/${PRIMARY_KEY_ID}.yaml" ]; then
        echo "Invalid ${PRIMARY_KEY_REPO}: ${PRIMARY_KEY_ID}"
        exit 1
    fi
fi



function get_meta() {
    local key=$1
    shift 1
    get_metadata_repo_entry "$BACKUP_DIR/${PATCHERG_TASK_NAME}${key}" $@
}
function get_fs() {
    local key=$1
    shift 1
    get_filesystem_repo_entry "$BACKUP_DIR/${PATCHERG_TASK_NAME}${key}" $@
}
function get_blob() {
    local key=$1
    shift 1
    get_blob_repo_entry "$BACKUP_DIR/${PATCHERG_TASK_NAME}${key}" $@
}
function lookup_meta_key() {
    get_metadata_key $@
}

#
#export PATCH_DIFF_META=$(get_meta ".patch_diff_meta" "$PATCH_DIFF_META_ID")
#export PATCH_DIFF=$(get_blob ".patch_diff" "$PATCH_DIFF_META_ID")
#export POI_REPORT_ID=$(lookup_meta_key "$PATCH_DIFF_META" ".poi_report_id")
export CRS_TASK=$(get_meta ".crs_task" "$PRIMARY_KEY_ID")
export PROJECT_ID=$(lookup_meta_key "$CRS_TASK" ".pdt_task_id")
export CRS_TASKS_ANALYSIS_SOURCES=$(get_fs ".crs_tasks_analysis_sources" "$PROJECT_ID")
export PROJECT_NAME=$(lookup_meta_key "$CRS_TASK" ".project_name")
export PROJECT_METADATA=$(get_meta ".project_metadata" "$PROJECT_ID")
export OSS_FUZZ_REPO=$(get_fs ".oss_fuzz_repo" "$PROJECT_ID")

if [ -z "${OUTPUT_DIR:-}" ]; then
    export OUTPUT_DIR=$(mktemp -d)
    echo "Created output dir: $OUTPUT_DIR"
fi

mkdir -p /shared/patchery/

export PATCH_REQUEST_META="$(mktemp -d -p /shared/patcherg/)"
export PATCH_BYPASS_REQUESTS="$(mktemp -d -p /shared/patcherg/)"
export EMPERORS_CRASH_SUBMISSION_EDICTS="$(mktemp -d -p /shared/patcherg/)"
export EMPERORS_PATCH_SUBMISSION_EDICTS="$(mktemp -d -p /shared/patcherg/)"

export ANALYSIS_GRAPH_BOLT_URL=bolt://neo4j:helloworldpdt@localhost:7687
export LOCAL_RUN="${LOCAL_RUN:-1}"

./run_patcherg.sh