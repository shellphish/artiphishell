#!/bin/bash

set -eu
set -o pipefail

source /shellphish/libs/test-utils/backup-handling-utils.sh

BACKUP_DIR="${1:-}"
CRASHING_INPUT_ID="${2:-}"
OUTPUT_DIR="${OUTPUT_DIR:-}"

export LITELLM_KEY='sk-artiphishell-da-best!!!'
export AIXCC_LITELLM_HOSTNAME='http://wiseau.seclab.cs.ucsb.edu:666'
export USE_LLM_API="1"

TASK_NAME=dyva_agent
PRIMARY_KEY_REPO=crashing_input

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

if [ -z "${CRASHING_INPUT_ID}" ]; then
    echo "Available CRASHING_INPUT_IDs to run: "
    for f in "${BACKUP_DIR}/${TASK_NAME}.${PRIMARY_KEY_REPO}"/*; do
        echo "$(basename "${f%.yaml}")"
    done
    echo "Which CRASHING_INPUT_ID would you like to run?"
    read -r CRASHING_INPUT_ID

    # ensure that the CRASHING_INPUT_ID exists
    if [ ! -f "${BACKUP_DIR}/${TASK_NAME}.${PRIMARY_KEY_REPO}/${CRASHING_INPUT_ID}" ]; then
        echo "Invalid CRASHING_INPUT_ID: ${CRASHING_INPUT_ID}"
        exit 1
    fi
fi

# if the CRASHING_INPUT_ID somehow does not exist, then exit
echo "$BACKUP_DIR"
if [ ! -f "${BACKUP_DIR}/${TASK_NAME}.${PRIMARY_KEY_REPO}/${CRASHING_INPUT_ID}" ]; then
    echo "Invalid CRASHING_INPUT_ID: ${CRASHING_INPUT_ID}"
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

export CRASHING_INPUT_ID="$CRASHING_INPUT_ID"
export CRASHING_INPUT=$(get_blob "dyva_agent.crashing_input" "$CRASHING_INPUT_ID")

export POI_REPORT=$(get_blob "poiguy.poi_report" "${CRASHING_INPUT_ID}")

export DYVA_BUILD_ID=$(lookup_meta_key "$POI_REPORT" ".build_configuration_id")
export DYVA_BUILD_ARTIFACT=$(get_fs "dyva_build.dyva_build_artifact" "$DYVA_BUILD_ID")

export BUILD_CONFIGURATION=$(get_blob "dyva_build.build_configuration" "${DYVA_BUILD_ID}.yaml")
export BUILD_CONFIGURATION_SANITIZER=$(lookup_meta_key "$BUILD_CONFIGURATION" ".sanitizer")
export BUILD_CONFIGURATION_ARCHITECTURE=$(lookup_meta_key "$BUILD_CONFIGURATION" ".architecture")

export CRS_TASK_ID=$(lookup_meta_key "$BUILD_CONFIGURATION" ".project_id")
export CRS_TASK=$(get_meta "pipeline_input.crs_task" "$CRS_TASK_ID")
export CRS_PROJECT_NAME=$(lookup_meta_key "$CRS_TASK" ".project_name")

export OSS_FUZZ_PROJECT_ID=$(lookup_meta_key "$POI_REPORT" ".project_id")
export OSS_FUZZ_PROJECT=$(get_fs "pipeline_input.oss_fuzz_repo" "$OSS_FUZZ_PROJECT_ID")
export OSS_FUZZ_PROJECT_DIR="${OSS_FUZZ_PROJECT}/projects/${CRS_PROJECT_NAME}"

export PROJECT_METADATA=$(get_blob "analyze_target.metadata_path" "${OSS_FUZZ_PROJECT_ID}.yaml")
export PROJECT_NAME=$(lookup_meta_key "$PROJECT_METADATA" ".shellphish.project_name")

if [ -z "$DYVA_BUILD_ARTIFACT" ] || [ -z "$POI_REPORT" ] || [ -z "$CRASHING_INPUT" ]; then
    echo "Missing required variables"
    echo "DYVA_BUILD_ARTIFACT: $DYVA_BUILD_ARTIFACT"
    echo "POI_REPORT: $POI_REPORT"
    echo "CRASHING_INPUT: $CRASHING_INPUT"
    echo "OSS_FUZZ_PROJECT: $OSS_FUZZ_PROJECT"
    exit 1
fi

if [ -z "$OUTPUT_DIR" ]; then
    export OUTPUT_DIR=$(mktemp -d)
    echo "Created output dir: $OUTPUT_DIR"
fi

export LOCAL_VARIABLE_REPORT="${OUTPUT_DIR}/agents.yaml" # {{out_locals | shquote}}
export LOCAL_VARIABLE_REPORT="$LOCAL_VARIABLE_REPORT"

# /app/run_scripts/run-build-dyva.sh
oss-fuzz-build-image --instrumentation shellphish_dyva --build-runner-image $OSS_FUZZ_PROJECT_DIR
/app/run_scripts/run-dyva-agent.sh
echo "Created output dir: $OUTPUT_DIR"