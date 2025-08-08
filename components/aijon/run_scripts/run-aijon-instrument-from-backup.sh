#!/bin/bash

set -eu
set -o pipefail

source /shellphish/libs/test-utils/backup-handling-utils.sh

BACKUP_DIR="${1:-}"
PROJECT_ID="${2:-}"
OUTPUT_DIR="${OUTPUT_DIR:-}"

MODE="codeswipe"
DIFF_PATCH_FILE="${DIFF_PATCH_FILE:-}"
CODESWIPE_REPORT="${CODESWIPE_REPORT:-}"

export LITELLM_KEY='sk-artiphishell-da-best!!!'
export AIXCC_LITELLM_HOSTNAME='http://wiseau.seclab.cs.ucsb.edu:666'
export USE_LLM_API="1"

TASK_NAME=pipeline_input
PRIMARY_KEY_REPO=project_id

if [ -z "${BACKUP_DIR}" ]; then
    num_backups=$(ls /aixcc-backups/ | wc -l)
    if [ "$num_backups" -eq 0 ]; then
        echo "No backups found in /aixcc-backups/"
        exit 1
    elif [ "$num_backups" -eq 1 ]; then
        BACKUP_NAME=$(ls /aixcc-backups/)
        echo "Only one backup found: ${BACKUP_NAME}"
    else
        echo "Available backups (in /aixcc-backups/):"
        ls /aixcc-backups/
        echo "Which backup would you like to use?"
        read -r BACKUP_NAME
        # ensure that the backup directory exists
        if [ ! -d "/aixcc-backups/${BACKUP_NAME}" ]; then
            echo "Invalid backup directory: ${BACKUP_NAME}"
            exit 1
        fi
    fi
    BACKUP_DIR="/aixcc-backups/${BACKUP_NAME}"
fi

if [ -z "${PROJECT_ID}" ]; then
    num_build_configs=$(ls "${BACKUP_DIR}/${TASK_NAME}.${PRIMARY_KEY_REPO}" | wc -l)
    if [ "$num_build_configs" -eq 0 ]; then
        echo "No project IDs found in ${BACKUP_DIR}/${TASK_NAME}.${PRIMARY_KEY_REPO}"
        exit 1
    elif [ "$num_build_configs" -eq 1 ]; then
        yaml_file=$(ls "${BACKUP_DIR}/${TASK_NAME}.${PRIMARY_KEY_REPO}")
        PROJECT_ID="${yaml_file%.yaml}"
        echo "Only one project ID found: ${PROJECT_ID}"
    else
        echo "Available BUILD_CONFIGURATIONs to run: "
        for f in "${BACKUP_DIR}/${TASK_NAME}.${PRIMARY_KEY_REPO}"/*; do
            echo "$(basename "${f%.yaml}")"
        done
        echo "Which BUILD_CONFIGURATION would you like to run?"
        read -r PROJECT_ID
    fi

    # ensure that the PROJECT_ID exists
    if [ ! -f "${BACKUP_DIR}/${TASK_NAME}.${PRIMARY_KEY_REPO}/${PROJECT_ID}.yaml" ]; then
        echo "Invalid PROJECT_ID: ${PROJECT_ID}"
        exit 1
    fi
fi

if [ -z "${MODE}" ]; then
    CODESWIPE_DIR=$BACKUP_DIR/aijon_instrument_from_codeswipe.done
    DIFF_DIR=$BACKUP_DIR/aijon_instrument_from_diff.done
    echo "Here are the available modes:"
    if [ -f "${CODESWIPE_DIR}/${PROJECT_ID}.yaml" ]; then
        echo "codeswipe"
    fi
    if [ -f "${DIFF_DIR}/${PROJECT_ID}.yaml" ]; then
        echo "diff"
    fi
    echo "Which mode would you like to run?"
    read -r MODE
fi


echo "$BACKUP_DIR"
if [ ! -f "${BACKUP_DIR}/${TASK_NAME}.${PRIMARY_KEY_REPO}/${PROJECT_ID}.yaml" ]; then
    echo "Invalid PROJECT_ID: ${PROJECT_ID}"
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
if [ -z "$OUTPUT_DIR" ]; then
    export OUTPUT_DIR=$(mktemp -d)
    echo "Created output dir: $OUTPUT_DIR"
fi

export SERVICE_FOLDER=$(echo $SERVICE_FOLDER_COMMAND | bash)
/aijon/run_scripts/start_analysis_graph.sh "$BACKUP_DIR"
export ANALYSIS_GRAPH_PASSWORD=$(grep -m1 "ANALYSIS_GRAPH_BOLT_URL" $BACKUP_DIR/analyze_target.logs/$PROJECT_ID | grep -oP 'ANALYSIS_GRAPH_BOLT_URL=bolt://[^:]+:\K[^@]+' |  cut -d' ' -f1)
export ANALYSIS_GRAPH_BOLT_URL="bolt://neo4j:$ANALYSIS_GRAPH_PASSWORD@172.17.0.1:7687"

export CRS_TASK_ANALYSIS_SOURCE=$(get_fs "aijon_instrument_from_codeswipe.project_analysis_source" "$PROJECT_ID")
export FULL_FUNCTION_INDICES=$(get_blob "generate_full_function_index.target_functions_index" "$PROJECT_ID")
export TARGET_FUNCTIONS_JSONS_DIR=$(get_fs "generate_full_function_index.target_functions_jsons_dir" "$PROJECT_ID")

if [ "$MODE" == "codeswipe" ]; then
    export CODESWIPE_REPORT=$(get_blob "aijon_instrument_from_codeswipe.codeswipe_ranking" "$PROJECT_ID")
elif [ "$MODE" == "diff" ]; then
    export DIFF_PATCH_FILE=$(get_blob "aijon_instrument_from_diff.crs_task_diff" "$PROJECT_ID")
else
    echo "Invalid mode specified: ${MODE}. Use 'codeswipe' or 'diff'."
    exit 1
fi

export LOCAL_RUN="1"
export POI_TYPE="$MODE"
export INSTRUMENTATION_ARTIFACTS="$OUTPUT_DIR"

export PROJECT_ID=${PROJECT_ID}
export PROJECT_NAME=$(lookup_meta_key "$BACKUP_DIR/${TASK_NAME}.${PRIMARY_KEY_REPO}/${PROJECT_ID}.yaml" ".project_name")
PROJECT_METADATA=$(get_blob "dyva_agent.project_metadata" "$PROJECT_ID.yaml")
export LANGUAGE=$(lookup_meta_key "$PROJECT_METADATA" ".language")

/aijon/run_scripts/run-aijon-instrument.sh
echo "Created output dir: $OUTPUT_DIR"
