#!/bin/bash

set -eu

source /shellphish/libs/test-utils/backup-handling-utils.sh

BACKUP_DIR="${1:-}"
PRIMARY_KEY_ID="${2:-}"
POI_REPORTS_DIR="${POI_REPORTS_DIR:-}"

export LITELLM_KEY='sk-artiphishell-da-best!!!'
export AIXCC_LITELLM_HOSTNAME='http://wiseau.seclab.cs.ucsb.edu:666'
export USE_LLM_API=1

TASK_NAME=grammar_agent_reproduce_losan_pov
PRIMARY_KEY_REPO=losan_pov_report_representative_crashing_input_metadata_id

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
set -x

echo "Using losan pov report representative metadata info: ${PRIMARY_KEY_ID}"
export REPLICA_ID=0
export LOSAN_POV_REPORT_REPRESENTATIVE_CRASHING_INPUT_ID="${PRIMARY_KEY_ID}"
export LOSAN_POV_REPORT_REPRESENTATIVE_CRASHING_INPUT_METADATA_FILE=$(get_meta grammar_agent_reproduce_losan_pov.losan_pov_report_representative_crashing_input_metadata_fp/ ${LOSAN_POV_REPORT_REPRESENTATIVE_CRASHING_INPUT_ID})
export HARNESS_INFO_ID=$(lookup_meta_key "$LOSAN_POV_REPORT_REPRESENTATIVE_CRASHING_INPUT_METADATA_FILE" ".harness_info_id")
export HARNESS_INFO_FILE="${HARNESS_INFO_FILE:-$(get_meta grammar_guy_fuzz.harness_info_fp/ ${HARNESS_INFO_ID})}"
export PROJECT_ID=${PROJECT_ID:-$(lookup_meta_key "$HARNESS_INFO_FILE" ".project_id")}
export BUILD_CONFIGURATION_ID=$(lookup_meta_key "$HARNESS_INFO_FILE" ".build_configuration_id")
export COVERAGE_BUILD_ARTIFACT=$(get_fs grammar_agent_reproduce_losan_pov.coverage_build_artifact ${PROJECT_ID})
export LOSAN_BUILD_ARTIFACT_PATH=$(get_fs grammar_agent_reproduce_losan_pov.losan_build_artifact_path ${BUILD_CONFIGURATION_ID})
export PROJECT_NAME=$(lookup_meta_key "$HARNESS_INFO_FILE" ".project_name")
export CP_HARNESS_NAME=$(lookup_meta_key "$HARNESS_INFO_FILE" ".cp_harness_name")

export FUZZER_SYNC_DIR="/shared/fuzzer_sync/${PROJECT_NAME}-${CP_HARNESS_NAME}-${HARNESS_INFO_ID}/"
mkdir -p "${FUZZER_SYNC_DIR}"
echo "Using fuzzer sync dir: ${FUZZER_SYNC_DIR}"

echo "Running grammar_guy with backup dir: ${BACKUP_DIR}"
echo "Exporting seeds to triage to: ${SEEDS_TO_TRIAGE_DIR}"
echo "Exporting events to: ${EVENTS_DIR}"
/shellphish/grammar_guy/run-gg-targeted-reproducer-agent.sh