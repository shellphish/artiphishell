#!/bin/bash

set -eu

source /shellphish/libs/test-utils/backup-handling-utils.sh

export LOCAL_RUN=True

RESTART_SERVICES="${RESTART_SERVICES:-False}"
BACKUP_DIR="${1:-}"
PRIMARY_KEY_ID="${2:-}"
POI_REPORTS_DIR="${POI_REPORTS_DIR:-}"

BACKUP_NAME=$(basename "$BACKUP_DIR")
export BACKUP_NAME

# export PDT_AGENT_SECRET=$(grep "PDT_AGENT_SECRET" $BACKUP_DIR/k8s_describe_pods.txt | head -n 1 | cut -d "'" -f 2)

# export LITELLM_KEY='sk-PhMkn-ug9XmXSGLryqENvA'
# export AIXCC_LITELLM_HOSTNAME='http://lite.tianleyu.com:4000'
export AIXCC_LITELLM_HOSTNAME="http://wiseau.seclab.cs.ucsb.edu:666/"
export LITELLM_KEY="sk-artiphishell-da-best!!!"
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
    echo "${BACKUP_DIR}/${TASK_NAME}.${PRIMARY_KEY_REPO}"
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

export HARNESS_INFO_ID="${PRIMARY_KEY_ID}"
export HARNESS_INFO_FILE="${HARNESS_INFO_FILE:-$(get_meta grammar_guy_fuzz.harness_info_fp/ ${HARNESS_INFO_ID})}"
export PROJECT_ID=${PROJECT_ID:-$(lookup_meta_key "$HARNESS_INFO_FILE" ".project_id")}
export BUILD_CONFIGURATION_ID=$(lookup_meta_key "$HARNESS_INFO_FILE" ".build_configuration_id")
export PROJECT_NAME=$(lookup_meta_key "$HARNESS_INFO_FILE" ".project_name")
export PROJECT_METADATA_PATH=$(get_meta "poiguy.project_metadata_path" "$PROJECT_ID")
export PROJECT_LANGUAGE=$(lookup_meta_key $PROJECT_METADATA_PATH ".language")
export OSS_FUZZ_REPO_PATH=$(get_fs "pipeline_input.oss_fuzz_repo" "$PROJECT_ID")
export DEBUG_BUILD_ARTIFACT=$(get_fs povguy.debug_build_artifacts_path ${BUILD_CONFIGURATION_ID})
export COVERAGE_BUILD_ARTIFACT=$(get_fs coverage_build_c.coverage_build_artifacts ${PROJECT_ID})
export DYVA_BUILD_ARTIFACT=$(get_fs "dyva_build.dyva_build_artifact" "$BUILD_CONFIGURATION_ID")
export OSS_FUZZ_PROJECT_SRC=$(get_fs analyze_target.project_analysis_sources ${PROJECT_ID})
export FUNCTIONS_BY_FILE_INDEX=$(get_blob "generate_full_function_index.functions_by_file_index_json" "$PROJECT_ID")
export TARGET_METADATA=$(get_meta "poiguy.project_metadata_path" "$PROJECT_ID")
export FUNCTIONS_INDEX=$(get_blob grammar_guy_fuzz.functions_index ${PROJECT_ID})
export TARGET_FUNCTIONS_JSONS_DIR=$(get_fs grammar_guy_fuzz.functions_jsons_dir ${PROJECT_ID})
export AGGREGATED_HARNESS_INFO=$(get_meta "quick_seed.aggregated_harness_info" ${PROJECT_ID})
export ANALYSIS_GRAPH_PASSWORD=$(grep -m1 "ANALYSIS_GRAPH_BOLT_URL" $BACKUP_DIR/pydatatask_agent.logs/1 | grep -oP 'ANALYSIS_GRAPH_BOLT_URL=bolt://[^:]+:\K[^@]+' |  cut -d' ' -f1)
export ANALYSIS_GRAPH_BOLT_URL="bolt://neo4j:$ANALYSIS_GRAPH_PASSWORD@172.17.0.1:7687"

# Testing sarif
export SARIF_UID="cafebabe0000000000000000000000000"
#export SARIF_PATH="/aixcc-backups/sqlite3.sarif"
export SARIF_PATH="/aixcc-backups/mockcp.sarif"
#export SARIF_PATH="/aixcc-backups/cups2bad.sarif"
#export SARIF_PATH="/aixcc-backups/mock3.sarif"
#export SARIF_PATH="/aixcc-backups/assimp.sarif"
#export SARIF_PATH="/aixcc-backups/libpng2.sarif"
#export SARIF_PATH="/aixcc-backups/libpng2.sarif"

export SARIF_META="/aixcc-backups/c83e974422f04d41b8ffad0edb35d4dc.yaml"

# Get a random path to save the sarif file
export OUT_FILE_PATH=$(mktemp)
export SARIF_HEARTBEAT_PATH=$(mktemp)
export SARIFGUYMODE="reasonable"

echo "Emitting heartbeat to $SARIF_HEARTBEAT_PATH"
echo -e "sarifguy_heartbeat:\n  timestamp: $(date -Iseconds)\n  project_name: $PROJECT_NAME" > $SARIF_HEARTBEAT_PATH


./run.sh