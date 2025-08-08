#!/bin/bash

set -e
set -u
set -o pipefail
set -x

source /shellphish/libs/test-utils/backup-handling-utils.sh

DELTA="${1:-}"
JAVA="${2:-}"
BACKUP_DIR="${3:-}"
PATCH_REQUESTS_ID="${4:-}"

# delta mode or full mode
if [ -z "${DELTA}" ]; then
    echo "Would you like to run in delta mode? (yes/no)"
    read -r DELTA
fi

if [ -z "${JAVA}" ]; then
    echo "Would you like to run in Java mode? (yes/no)"
    read -r JAVA
fi

#if [ -z "${HYBRID_MODE}" ]; then
#    echo "Would you like to run in heavy mode? (yes/no)"
#    read -r HYBRID_MODE
#fi

if [ "${DELTA}" == "yes" ]; then
    DELTA="--delta-mode"
    if [ "${JAVA}" == "yes" ]; then
        KUMUSHI_TASK_NAME=kumushi_delta_java
    else
       JAVA=""
       KUMUSHI_TASK_NAME=kumushi_delta
    fi
else
    DELTA=""
    if [ "${JAVA}" == "yes" ]; then
        KUMUSHI_TASK_NAME=kumushi_java
    else
        JAVA=""
        KUMUSHI_TASK_NAME=kumushi
    fi
fi

export DELTA="${DELTA}"
export JAVA="${JAVA}"
export HYBRID_MODE=""

PRIMARY_KEY_REPO=patch_requests_meta

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

if [ -z "${PATCH_REQUESTS_ID}" ]; then
    echo "Available PATCH_REQUESTS_ID to run: "
    for f in "${BACKUP_DIR}/${KUMUSHI_TASK_NAME}.${PRIMARY_KEY_REPO}"/*; do
        echo "$(basename "${f%.yaml}")"
    done
    echo "Which PATCH_REQUESTS_ID would you like to run?"
    read -r PATCH_REQUESTS_ID

    # ensure that the POI_REPORT_ID exists
    if [ ! -f "${BACKUP_DIR}/${KUMUSHI_TASK_NAME}.${PRIMARY_KEY_REPO}/${PATCH_REQUESTS_ID}.yaml" ]; then
        echo "Invalid PATCH_REQUESTS_ID: ${PATCH_REQUESTS_META}"
        exit 1
    fi
fi

function get_meta() {
    local key=$1
    shift 1
    get_metadata_repo_entry "$BACKUP_DIR/${KUMUSHI_TASK_NAME}${key}" $@
}
function get_fs() {
    local key=$1
    shift 1
    get_filesystem_repo_entry "$BACKUP_DIR/${KUMUSHI_TASK_NAME}${key}" $@
}
function get_blob() {
    local key=$1
    shift 1
    get_blob_repo_entry "$BACKUP_DIR/${KUMUSHI_TASK_NAME}${key}" $@
}
function lookup_meta_key() {
    get_metadata_key $@
}

FULL_INDEX="generate_full_function_index"
function get_full_fs() {
    local key=$1
    shift 1
    get_filesystem_repo_entry "$BACKUP_DIR/${FULL_INDEX}${key}" $@
}

function get_full_blob() {
    local key=$1
    shift 1
    get_blob_repo_entry "$BACKUP_DIR/${FULL_INDEX}${key}" $@
}

export PATCH_REQUESTS_META_PATH=$(get_meta ".patch_requests_meta" "$PATCH_REQUESTS_ID")
export POI_REPORT_ID=$(lookup_meta_key "$PATCH_REQUESTS_META_PATH" ".poi_report_id")

export POI_REPORT_PATH=$(get_blob ".poi_report" "$POI_REPORT_ID")

export BUILD_CONFIGURATION=$(lookup_meta_key "$POI_REPORT_PATH" ".build_configuration_id")

export PROJECT_ID=$(lookup_meta_key "$POI_REPORT_PATH" ".project_id")
export PROJECT_NAME=$(lookup_meta_key "$POI_REPORT_PATH" ".project_name")
export PROJECT_METADATA=$(get_meta ".project_metadata" "$PROJECT_ID")
# source root
CRS_TASK_ANALYSIS_SOURCE=$(get_fs ".crs_tasks_analysis_source" "$PROJECT_ID")
# oss fuzz repor
OSS_FUZZ_REPO=$(get_fs ".oss_fuzz_repo" "$PROJECT_ID")
export CRASHING_INPUT_PATH=$(get_blob ".crashing_input_path" "$POI_REPORT_ID")

export POI_REPORT=$(get_blob ".poi_report" "$POI_REPORT_ID")

export FULL_FUNCTIONS_JSONS_DIR=$(get_full_fs ".target_functions_jsons_dir" "$PROJECT_ID")
export COMMIT_FUNCTIONS_JSONS_DIR=$(get_fs ".commit_functions_jsons_dir" "$PROJECT_ID")
export FULL_FUNCTIONS_INDEX=$(get_full_blob ".target_functions_index" "$PROJECT_ID")
export COMMIT_FUNCTIONS_INDEX=$(get_blob ".commit_functions_index" "$PROJECT_ID")
export COVERAGE_BUILD_ARTIFACTS=$(get_fs ".coverage_build_artifacts" "$PROJECT_ID")
export DEBUG_BUILD_ARTIFACTS=$(get_fs ".debug_build_artifacts" "$BUILD_CONFIGURATION")
export DIFFGUY_REPORTS=$(get_fs ".diffguy_reports" "$PROJECT_ID")
export CRASHING_INPUT_EXPLORATION_PATH=$(get_fs ".crashing_input_exploration_path" "$POI_REPORT_ID")
export PATCH_REQUEST_META=$(get_meta ".patch_requests_meta" "$PATCH_REQUESTS_ID")


export DYVA_REPORT=$(get_meta ".dyva_report" "$PATCH_REQUESTS_ID")


if [ "${HYBRID_MODE}" == "yes" ] ; then
  export AFLPP_BUILD_ARTIFACTS=$(get_fs ".aflpp_build_artifacts" "$BUILD_CONFIGURATION")
  export CRASHING_INPUT_EXPLORATION_PATH=$(get_fs ".crashing_input_exploration_path" "$POI_REPORT_ID")
fi

export CRS_TASK_ANALYSIS_SOURCE="${CRS_TASK_ANALYSIS_SOURCE}"
export OSS_FUZZ_REPO="${OSS_FUZZ_REPO}"

mkdir -p /shared/kumushi/output/
export KUMUSHI_OUTPUT="/shared/kumushi/output/kumushi_root_cause.yaml"


echo "Only Test kumushi on light mode for now"
# HEAVY_MODE=1
# export HEAVY_MODE="${HEAVY_MODE}"
export LOCAL_RUN=1
export LITELLM_KEY='sk-artiphishell-da-best!!!'
export AIXCC_LITELLM_HOSTNAME='http://wiseau.seclab.cs.ucsb.edu:666'
export USE_LLM_API=1
export LOG_LLM=0
export LOG_LEVEL=WARNING
export CODEQL_SERVER_URL='http://localhost:4000'
export ANALYSIS_GRAPH_BOLT_URL='bolt://neo4j:helloworldpdt@localhost:7687'
wget http://localhost:8000/llvm-dwarfdump -O /shellphish/libs/coveragelib/coveragelib/utils/llvm-dwarfdump
chmod +x /shellphish/libs/coveragelib/coveragelib/utils/llvm-dwarfdump
./run_kumushi.sh

