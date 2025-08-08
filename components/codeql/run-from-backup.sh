#!/bin/bash

set -eu
set -x

source /shellphish/libs/test-utils/backup-handling-utils.sh

BACKUP_DIR="${1:-}"
PRIMARY_KEY_ID="${2:-}"
POI_REPORTS_DIR="${POI_REPORTS_DIR:-}"

TASK_NAME=codeql_build
PRIMARY_KEY_REPO=project_id

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

# export SEEDS_TO_TRIAGE_DIR="${OUTPUT_DIR}/seeds_to_triage"
# export EVENTS_DIR="${OUTPUT_DIR}/events"
# mkdir -p "${SEEDS_TO_TRIAGE_DIR}" "${EVENTS_DIR}"

# echo "Using harness info file: ${PRIMARY_KEY_ID}"
# export HARNESS_INFO_ID="${PRIMARY_KEY_ID}"
# export HARNESS_INFO_FILE="${HARNESS_INFO_FILE:-$(get_meta grammar_guy_fuzz.harness_info_fp/ ${HARNESS_INFO_ID})}"
# export PROJECT_ID=${PROJECT_ID:-$(lookup_meta_key "$HARNESS_INFO_FILE" ".project_id")}
# export BUILD_CONFIGURATION_ID=$(lookup_meta_key "$HARNESS_INFO_FILE" ".build_configuration_id")
# export COVERAGE_BUILD_ARTIFACT=$(get_fs grammar_guy_fuzz.coverage_build_artifact ${BUILD_CONFIGURATION_ID})
# export PROJECT_NAME=$(lookup_meta_key "$HARNESS_INFO_FILE" ".project_name")
# export CP_HARNESS_NAME=$(lookup_meta_key "$HARNESS_INFO_FILE" ".cp_harness_name")

# export FUNCTIONS_FULL_INDEX_PATH=$(get_blob grammar_guy_fuzz.functions_index ${PROJECT_ID})
# export FUNCTIONS_FULL_JSONS_DIR=$(get_fs grammar_guy_fuzz.functions_jsons_dir ${PROJECT_ID})


export PROJ_ID=$PRIMARY_KEY_ID
export PROJ_META=$(get_meta codeql_build.meta/ ${PRIMARY_KEY_ID})
export CRS_TASK_META=$(get_meta codeql_build.crs_task/ ${PRIMARY_KEY_ID})
export CP_NAME=$(lookup_meta_key "$CRS_TASK_META" ".project_name")
export LANG=$(lookup_meta_key "$PROJ_META" ".language")
export ANALYSIS_GRAPH_BOLT_URL='bolt://neo4j:helloworldpdt@172.17.0.1:7687'
export CODEQL_SERVER_URL='http://172.17.0.1:4000'
export FUNC_RESOLVER_URL='http://172.17.0.1:4033'

echo "init db"
export CODEQL_ZIP_FOLDER=$(get_fs codeql_build.codeql_database_path/ ${PROJ_ID})
export CODEQL_BUILDLESS_ZIP_FOLDER=$(get_fs codeql_build.codeql_database_path_buildless/ ${PROJ_ID})
codeql-upload-db --cp_name $CP_NAME --project_id $PROJ_ID --db_file $CODEQL_ZIP_FOLDER/sss-codeql-database.zip --language $LANG 2> /dev/null || true
codeql-upload-db --cp_name "${CP_NAME}-buildless" --project_id $PROJ_ID --db_file $CODEQL_BUILDLESS_ZIP_FOLDER/sss-codeql-database-no-build.zip --language $LANG 2> /dev/null || true

echo "init function resolver"
export FUNCTION_INDEX_DIR=$BACKUP_DIR/generate_full_function_index.target_functions_index
export FUNCTION_INDEX_PATH=$(get_blob generate_full_function_index.target_functions_index ${PROJ_ID})
export FUNCTION_JSON_DIR=$(get_fs generate_full_function_index.target_functions_jsons_dir ${PROJ_ID})
# echo "FUNC_IDX_FOLDER: $FUNC_IDX_FOLDER"
# echo "FUNC_JSON_FOLDER: $FUNC_JSON_FOLDER"
# Archive the function index and jsons
pushd $FUNCTION_INDEX_DIR > /dev/null
rm -f functions_index.tar
tar -cvf functions_index.tar $PROJ_ID > /dev/null
popd > /dev/null
pushd $FUNCTION_JSON_DIR > /dev/null
rm -f functions_jsons.tar
tar -cvf functions_jsons.tar ./* > /dev/null
popd > /dev/null
# make a temp dir for the function resolver
rm -rf /tmp/func_resolver
mkdir -p /tmp/func_resolver/functions_index
mkdir -p /tmp/func_resolver/functions_jsons
# copy the function index and jsons to the temp dir
cp $FUNCTION_INDEX_DIR/functions_index.tar /tmp/func_resolver/functions_index
cp $FUNCTION_JSON_DIR/functions_jsons.tar /tmp/func_resolver/functions_jsons
# Make the big tar
pushd /tmp/func_resolver > /dev/null
tar -cvf data.tar ./functions_index/functions_index.tar ./functions_jsons/functions_jsons.tar > /dev/null
popd > /dev/null
# Upload the function index and jsons to the function resolver
python3 ./init_func_resolver.py
# cp /tmp/func_resolver/data.tar ./
rm -rf /tmp/func_resolver

echo "Running codeql analysis with backup dir: ${BACKUP_DIR}"
# echo "Exporting seeds to triage to: ${SEEDS_TO_TRIAGE_DIR}"
# echo "Exporting events to: ${EVENTS_DIR}"
python3 /shellphish/codeql/callgraph/analysis_query.py
