#!/bin/bash

set -eu
set -o pipefail

source /shellphish/libs/test-utils/backup-handling-utils.sh

BACKUP_DIR="${1:-}"
BUILD_CONFIGURATION_ID="${2:-}"
OUTPUT_DIR="${OUTPUT_DIR:-}"

export LITELLM_KEY='sk-artiphishell-da-best!!!'
export AIXCC_LITELLM_HOSTNAME='http://wiseau.seclab.cs.ucsb.edu:666'
export USE_LLM_API="1"

TASK_NAME=dyva_build
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

if [ -z "${BUILD_CONFIGURATION_ID}" ]; then
    echo "Available BUILD_CONFIGURATIONs to run: "
    for f in "${BACKUP_DIR}/${TASK_NAME}.${PRIMARY_KEY_REPO}"/*; do
        echo "$(basename "${f%.yaml}")"
    done
    echo "Which BUILD_CONFIGURATION would you like to run?"
    read -r BUILD_CONFIGURATION_ID

    # ensure that the BUILD_CONFIGURATION_ID exists
    if [ ! -f "${BACKUP_DIR}/${TASK_NAME}.${PRIMARY_KEY_REPO}/${BUILD_CONFIGURATION_ID}.yaml" ]; then
        echo "Invalid BUILD_CONFIGURATION_ID: ${BUILD_CONFIGURATION_ID}"
        exit 1
    fi
fi

# if the CRASHING_INPUT_ID somehow does not exist, then exit
echo "$BACKUP_DIR"
if [ ! -f "${BACKUP_DIR}/${TASK_NAME}.${PRIMARY_KEY_REPO}/${BUILD_CONFIGURATION_ID}.yaml" ]; then
    echo "Invalid BUILD_CONFIGURATION_ID: ${BUILD_CONFIGURATION_ID}"
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

export BUILD_CONFIGURATION_ID="$BUILD_CONFIGURATION_ID"
export BUILD_CONFIGURATION=$(get_blob "dyva_build.build_configuration" "${BUILD_CONFIGURATION_ID}.yaml")
export BUILD_CONFIGURATION_ARCHITECTURE=$(lookup_meta_key "$BUILD_CONFIGURATION" ".architecture")
export BUILD_CONFIGURATION_SANITIZER=$(lookup_meta_key "$BUILD_CONFIGURATION" ".sanitizer")

export CRS_TASK_ID=$(lookup_meta_key "$BUILD_CONFIGURATION" ".project_id")

export CRS_PROJECT_NAME=$(lookup_meta_key "$BUILD_CONFIGURATION" ".project_name")
export OSS_FUZZ_PROJECT=$(get_fs "pipeline_input.oss_fuzz_repo" "$CRS_TASK_ID")
export OSS_FUZZ_PROJECT_DIR="${OSS_FUZZ_PROJECT}/projects/${CRS_PROJECT_NAME}"
export PROJECT_SOURCE=$(get_fs "analyze_target.project_analysis_sources" "$CRS_TASK_ID")

if [ -z "$OUTPUT_DIR" ]; then
    export OUTPUT_DIR=$(mktemp -d)
    echo "Created output dir: $OUTPUT_DIR"
fi

export LOCAL_BUILD="1"
export DYVA_BUILD_ARTIFACT=${OUTPUT_DIR}

/app/run_scripts/run-dyva-build.sh
echo "Created output dir: $OUTPUT_DIR"