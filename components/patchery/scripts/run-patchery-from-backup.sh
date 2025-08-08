#!/bin/bash

set -e
set -u
set -o pipefail
set -x

source /shellphish/libs/test-utils/backup-handling-utils.sh

export GITHUB_CREDS_PATH="/root/.git-credentials"
INVARIANTS="${INVARIANTS:-}"
SMART_MODE="${1:-}"
DELTA_MODE="${2:-}"
BACKUP_DIR="${3:-}"
PATCH_REQUESTS_ID="${4:-}"
OUTPUT_DIR="${OUTPUT_DIR:-}"


export LITELLM_KEY='sk-artiphishell-da-best!!!'
export AIXCC_LITELLM_HOSTNAME='http://wiseau.seclab.cs.ucsb.edu:666'

if [ -z "${SMART_MODE}" ]; then
    echo "Would you like to run in smart mode? (yes/no)"
    read -r SMART_MODE
fi
if [ -z "${DELTA_MODE}" ]; then
    echo "Would you like to run in delta mode? (yes/no)"
    read -r DELTA_MODE
fi
if [ "${SMART_MODE}" == "yes" ]; then
    PATCHERY_TASK_NAME=patchery_smart
else
  if [ "${DELTA_MODE}" == "yes" ]; then
      PATCHERY_TASK_NAME=patchery_delta
  else
      PATCHERY_TASK_NAME=patchery
  fi
fi

PRIMARY_KEY_REPO=patch_requests_meta
if [ ! -z "${INVARIANTS}" ]; then
    PATCHERY_TASK_NAME=patchery_invariants
    PRIMARY_KEY_REPO=invariance_report
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

if [ -z "${PATCH_REQUESTS_ID}" ]; then
    echo "Available PATCH_REQUESTS_ID to run: "
    for f in "${BACKUP_DIR}/${PATCHERY_TASK_NAME}.${PRIMARY_KEY_REPO}"/*; do
        echo "$(basename "${f%.yaml}")"
    done
    echo "Which PATCH_REQUESTS_ID would you like to run?"
    read -r PATCH_REQUESTS_ID

    # ensure that the POI_REPORT_ID exists
    if [ ! -f "${BACKUP_DIR}/${PATCHERY_TASK_NAME}.${PRIMARY_KEY_REPO}/${PATCH_REQUESTS_ID}.yaml" ]; then
        echo "Invalid PATCH_REQUESTS_ID: ${PATCH_REQUESTS_META}"
        exit 1
    fi
fi

# if the POI_REPORT_ID somehow does not exist, then exit
echo "$BACKUP_DIR"
if [ ! -f "${BACKUP_DIR}/${PATCHERY_TASK_NAME}.${PRIMARY_KEY_REPO}/${PATCH_REQUESTS_ID}.yaml" ]; then
    echo "Invalid PATCH_REQUESTS_ID: ${PATCH_REQUESTS_ID}"
    exit 1
fi


function get_meta() {
    local key=$1
    shift 1
    get_metadata_repo_entry "$BACKUP_DIR/${PATCHERY_TASK_NAME}${key}" $@
}
function get_fs() {
    local key=$1
    shift 1
    get_filesystem_repo_entry "$BACKUP_DIR/${PATCHERY_TASK_NAME}${key}" $@
}
function get_blob() {
    local key=$1
    shift 1
    get_blob_repo_entry "$BACKUP_DIR/${PATCHERY_TASK_NAME}${key}" $@
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

if [ "${SMART_MODE}" == "yes" ]; then
    export KUMUSHI_REPORT=$(get_meta ".kumushi_output" "$PATCH_REQUESTS_ID")
else
    export KUMUSHI_REPORT=""
fi

export PATCH_REQUESTS_META_PATH=$(get_meta ".patch_requests_meta" "$PATCH_REQUESTS_ID")
export POI_REPORT_ID=$(lookup_meta_key "$PATCH_REQUESTS_META_PATH" ".poi_report_id")

export POI_REPORT_PATH=$(get_blob ".poi_report" "$POI_REPORT_ID")

export PROJECT_ID=$(lookup_meta_key "$POI_REPORT_PATH" ".project_id")
export CRS_TASK_ANALYSIS_SOURCE=$(get_fs ".crs_tasks_analysis_source" "$PROJECT_ID")
export CRASHING_INPUT_PATH=$(get_blob ".crashing_input_path" "$POI_REPORT_ID")
export SANITIZER_STRING=$(lookup_meta_key "$POI_REPORT_PATH" '.consistent_sanitizers[-1]')
export POI_REPORT=$(get_blob ".poi_report" "$POI_REPORT_ID")
export PROJECT_NAME=$(lookup_meta_key "$POI_REPORT_PATH" ".project_name")
export PROJECT_METADATA=$(get_meta ".project_metadata" "$PROJECT_ID")
export OSS_FUZZ_REPO=$(get_fs ".oss_fuzz_repo" "$PROJECT_ID")
export FULL_FUNCTIONS_JSONS_DIR=$(get_full_fs ".target_functions_jsons_dir" "$PROJECT_ID")
export COMMIT_FUNCTIONS_JSONS_DIR=$(get_fs ".commit_functions_jsons_dir" "$PROJECT_ID")
export FULL_FUNCTIONS_INDEX=$(get_full_blob ".target_functions_index" "$PROJECT_ID")
export COMMIT_FUNCTIONS_INDEX=$(get_blob ".commit_functions_index" "$PROJECT_ID")
export RAW_POVGUY_REPORT=$(get_meta ".povguy_pov_report_path" "$POI_REPORT_ID")
export PATCH_REQUESTS_META=$(get_meta ".patch_requests_meta" "$PATCH_REQUESTS_ID")


export MAX_ATTEMPTS="${MAX_ATTEMPTS:-10}"
export MAX_POIS="${MAX_POIS:-10}"

if [ -z "${OUTPUT_DIR}" ]; then
    export OUTPUT_DIR=$(mktemp -d)
    echo "Created output dir: $OUTPUT_DIR"
fi

export PATCH_OUTPUT_PATH="${OUTPUT_DIR}/patch" # {{out_patch | shquote}}
export PATCH_METADATA_OUTPUT_PATH="${OUTPUT_DIR}/patch.meta" # {{out_patch.cokeyed_dirs.meta | shquote}}
export BYPASSING_INPUTS="${OUTPUT_DIR}/bypassing_inputs" # {{bypasing_inputs | shquote}}

export LOCAL_RUN="${LOCAL_RUN:-1}"
export ANALYSIS_GRAPH_BOLT_URL='bolt://neo4j:helloworldpdt@localhost:7687'
./run-patchery.sh