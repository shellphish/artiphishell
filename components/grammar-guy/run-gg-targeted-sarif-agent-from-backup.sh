#!/bin/bash

set -eu

source /shellphish/libs/test-utils/backup-handling-utils.sh

BACKUP_DIR="${1:-}"
PRIMARY_KEY_ID="${2:-}"
POI_REPORTS_DIR="${POI_REPORTS_DIR:-}"

export LITELLM_KEY='sk-artiphishell-da-best!!!'
export AIXCC_LITELLM_HOSTNAME='http://wiseau.seclab.cs.ucsb.edu:666'
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

if [ -z "${OUTPUT_DIR:-}" ]; then
    export OUTPUT_DIR=$(mktemp -d)/
    echo "Created output dir: $POI_REPORTS_DIR"
fi

export SEEDS_TO_TRIAGE_DIR="${OUTPUT_DIR}/seeds_to_triage"
export EVENTS_DIR="${OUTPUT_DIR}/events"
mkdir -p "${SEEDS_TO_TRIAGE_DIR}" "${EVENTS_DIR}"


echo "Using harness info file: ${PRIMARY_KEY_ID}"
export HARNESS_INFO_ID="${PRIMARY_KEY_ID}"
export HARNESS_INFO_FILE="${HARNESS_INFO_FILE:-$(get_meta grammar_guy_fuzz.harness_info_fp/ ${HARNESS_INFO_ID})}"
export PROJECT_ID=${PROJECT_ID:-$(lookup_meta_key "$HARNESS_INFO_FILE" ".project_id")}
export BUILD_CONFIGURATION_ID=$(lookup_meta_key "$HARNESS_INFO_FILE" ".build_configuration_id")
export COVERAGE_BUILD_ARTIFACT=$(get_fs grammar_guy_fuzz.coverage_build_artifact ${BUILD_CONFIGURATION_ID})
export PROJECT_NAME=$(lookup_meta_key "$HARNESS_INFO_FILE" ".project_name")
export CP_HARNESS_NAME=$(lookup_meta_key "$HARNESS_INFO_FILE" ".cp_harness_name")

export FUNCTIONS_FULL_INDEX_PATH=$(get_blob grammar_guy_fuzz.functions_index ${PROJECT_ID})
export FUNCTIONS_FULL_JSONS_DIR=$(get_fs grammar_guy_fuzz.functions_jsons_dir ${PROJECT_ID})

echo "Running grammar_guy with backup dir: ${BACKUP_DIR}"
echo "Exporting seeds to triage to: ${SEEDS_TO_TRIAGE_DIR}"
echo "Exporting events to: ${EVENTS_DIR}"
/shellphish/grammar_guy/run-gg-targeted-sarif-agent.sh