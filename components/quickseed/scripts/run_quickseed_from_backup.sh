#!/bin/bash

set -e
set -u
set -o pipefail
set -x

source /shellphish/libs/test-utils/backup-handling-utils.sh

export LITELLM_KEY='sk-artiphishell-da-best!!!'
export AIXCC_LITELLM_HOSTNAME='http://wiseau.seclab.cs.ucsb.edu:666'

DELTA="${1:-}"
BACKUP_DIR="${2:-}"
PROJECT_ID="${3:-}"
INJECT_SARIF_REPORT="${4:-}"
SARIF_ID="${5:-}"

if [ -z "${DELTA}" ]; then
    echo "Would you like to run in delta mode? (yes/no)"
    read -r DELTA
fi

if [ "${DELTA}" == "yes" ]; then
  QUICKSEED_TASK_NAME=quick_seed_delta
  CODESWIPE_TASK_NAME=code_swipe_delta
else
  QUICKSEED_TASK_NAME=quick_seed
  CODESWIPE_TASK_NAME=code_swipe
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
PRIMARY_KEY_REPO=project_id

echo "$BACKUP_DIR"
if [ -z "${PROJECT_ID}" ]; then
    echo "Available Project Info to run: "
    for f in "${BACKUP_DIR}/${QUICKSEED_TASK_NAME}.${PRIMARY_KEY_REPO}"/*; do
        echo "$(basename "${f%.yaml}")"
    done
    echo "Which PROJECT_ID would you like to run?"
    read -r PROJECT_ID
fi

echo "$BACKUP_DIR"
if [ -z "${SARIF_ID}" ]; then
    # Check if there are any files in the directory
    files=("${BACKUP_DIR}/quick_seed_sarif.sarif_report"/*)
    if [ -e "${files[0]}" ]; then
        echo "Sarif report(s) found. Do you want to inject a sarif report? (y/n)"
        read -r INJECT_SARIF_REPORT
        if [[ "$INJECT_SARIF_REPORT" =~ ^[Yy]([Ee][Ss])?$ ]]; then
            echo "Available sarif reports to run: "
            for f in "${BACKUP_DIR}/quick_seed_sarif.sarif_report"/*; do
                echo "$(basename "${f%.yaml}")"
            done
            echo "Which SARIF_ID would you like to run?"
            read -r SARIF_ID
        else
            echo "Skipping sarif report injection."
        fi
    else
        echo "No sarif report files found in directory."
    fi
fi

export PROJECT_ID="${PROJECT_ID}"

function get_meta() {
    local key=$1
    shift 1
    get_metadata_repo_entry "$BACKUP_DIR/${QUICKSEED_TASK_NAME}${key}" $@
}

function get_fs() {
    local key=$1
    shift 1
    get_filesystem_repo_entry "$BACKUP_DIR/${QUICKSEED_TASK_NAME}${key}" $@
}
function get_blob() {
    local key=$1
    shift 1
    get_blob_repo_entry "$BACKUP_DIR/${QUICKSEED_TASK_NAME}${key}" $@
}
function lookup_meta_key() {
    get_metadata_key $@
}

AGGREGATED_HARNESS_INFO=$(get_meta ".aggregated_harness_info" "$PROJECT_ID")
echo "AGGREGATED_HARNESS_INFO: $AGGREGATED_HARNESS_INFO"
export AGGREGATED_HARNESS_INFO=$AGGREGATED_HARNESS_INFO


# SANITIZER_STRING=$(lookup_meta_key "${HARNESS_INFO}" ".sanitizer")
# export SANITIZER_STRING=$SANITIZER_STRING
# echo "Sanitizer: $SANITIZER_STRING"

# BUILD_CONFIGURATION_ID=$(lookup_meta_key "${AGGREGATED_HARNESS_INFO}" ".build_configuration_id")
# export BUILD_CONFIGURATION_ID=$BUILD_CONFIGURATION_ID
# echo "BUILD_CONFIGURATION_ID: $BUILD_CONFIGURATION_ID"

BUILD_CONFIGURATION_ID=$(basename "${BACKUP_DIR}/build_configuration_splitter.build_configurations_dir"/*.yaml .yaml)

export PROJECT_METADATA=$(get_meta ".project_metadata" "$PROJECT_ID")
export PROJECT_METADATA=$PROJECT_METADATA
echo "PROJECT_METADATA: $PROJECT_METADATA"

PROJECT_NAME=$(lookup_meta_key "${PROJECT_METADATA}" ".shellphish_project_name")
export PROJECT_NAME=$PROJECT_NAME
echo "PROJECT_NAME: $PROJECT_NAME"


export FULL_FUNCTIONS_JSONS_DIR=$(get_fs ".full_functions_jsons_dir" "$PROJECT_ID")
export FULL_FUNCTIONS_INDEX=$(get_blob ".full_functions_index" "$PROJECT_ID")
export COMMIT_FUNCTIONS_JSONS_DIR=$(get_fs ".commit_functions_jsons_dir" "$PROJECT_ID")
if [ -z "$(ls $COMMIT_FUNCTIONS_JSONS_DIR)" ]; then
    echo "Commit directory is empty"
    export COMMIT_FUNCTIONS_JSONS_DIR=""
fi
export CODEQL_SERVER_URL='http://localhost:4000'
export QUICKSEED_CODEQL_REPORT=$(get_blob ".quickseed_codeql_report" "$PROJECT_ID")


export QUICKSEED_CODESWIPE_REPORT=$(get_blob_repo_entry "$BACKUP_DIR/$CODESWIPE_TASK_NAME.codeswipe_rankings" "$PROJECT_ID")

# source root
CRS_TASK_ANALYSIS_SOURCE=$(get_fs ".crs_tasks_analysis_source" "$PROJECT_ID")
# oss fuzz repor
OSS_FUZZ_REPO=$(get_fs ".crs_tasks_oss_fuzz_repos" "$PROJECT_ID")

COVERAGE_BUILD_ARTIFACTS_PATH=$(get_fs ".coverage_build_artifacts" "$PROJECT_ID")

DEBUG_BUILD_ARTIFACTS_PATH=$(get_fs ".debug_build_artifacts" "$BUILD_CONFIGURATION_ID")
    
if [ -n "${SARIF_ID}" ]; then
    SARIF_REPORT=$(get_blob_repo_entry "$BACKUP_DIR/quick_seed_sarif.sarif_report" "$SARIF_ID")
    SARIF_METADATA_PATH=$(get_metadata_repo_entry "$BACKUP_DIR/quick_seed_sarif.sarif_meta_path" "$SARIF_ID")
else
    SARIF_REPORT=""
    SARIF_METADATA_PATH=""
fi

export COVERAGE_BUILD_ARTIFACTS="${COVERAGE_BUILD_ARTIFACTS_PATH}"
export DEBUG_BUILD_ARTIFACTS="${DEBUG_BUILD_ARTIFACTS_PATH}"
export CRS_TASK_ANALYSIS_SOURCE="${CRS_TASK_ANALYSIS_SOURCE}"
export OSS_FUZZ_REPO="${OSS_FUZZ_REPO}"
export SARIF_REPORT="${SARIF_REPORT}"
export SARIF_METADATA_PATH="${SARIF_METADATA_PATH}"
export CRASH_DIR_PASS_TO_POV=$(mktemp -d /shared/quickseed/crash_dir_pass_to_pov.XXXXXX)
export CRASH_METADATA_DIR_PASS_TO_POV=$(mktemp -d /shared/quickseed/crash_metadata_dir_pass_to_pov.XXXXXX)
export ANALYSIS_GRAPH_BOLT_URL='bolt://neo4j:helloworldpdt@172.17.0.1:7687'

export PDT_AGENT_URL=http://localhost:31839/
export PDT_AGENT_SECRET=12006812447233715615525536826868057872280
export LOCAL_RUN=1

export QUICKSEED_BACKUP_DIR=$(mktemp -d /tmp/backup.XXXXXX)
export QUICKSEED_LOG=${QUICKSEED_BACKUP_DIR}/quickseed.log

export QUICKSEED_PATH_BACKUP_REPORT=${QUICKSEED_BACKUP_DIR}/quickseed_path_backup_report.yaml
export QUICKSEED_CRASHING_SEED_BACKUP=${QUICKSEED_BACKUP_DIR}/quickseed_crashing_seed_backup
mkdir -p ${QUICKSEED_CRASHING_SEED_BACKUP}
if [ -n "${SARIF_REPORT}" ]; then
    export SARIF_RETRY_METADATA=${QUICKSEED_BACKUP_DIR}/sarif_retry_metadata.yaml
fi
/quickseed/scripts/run_quickseed.sh
