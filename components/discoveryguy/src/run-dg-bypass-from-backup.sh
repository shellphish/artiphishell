#!/bin/bash

set -eu

source /shellphish/libs/test-utils/backup-handling-utils.sh

export LOCAL_RUN=True
export DISCO_GUY_FROM="BYPASS"

export BACKUP_SEEDS_VAULT="/shared/dg_backup_seeds_vault"
export REPORT_DIR="/shared/reports"
mkdir -p $BACKUP_SEEDS_VAULT
mkdir -p $REPORT_DIR

BACKUP_DIR="${1:-}"
PRIMARY_KEY_ID="${2:-}"
POI_REPORTS_DIR="${POI_REPORTS_DIR:-}"


rm -rf /tmp/stats/*

BACKUP_NAME=$(basename "$BACKUP_DIR")
export BACKUP_NAME

# if the .$BACKUP_NAME exists, we can simply run the dg_cached_run.sh
if [ -f ./.dg-cached-runs/$BACKUP_NAME/dg_cached_run.sh ]; then
    echo "Running the cached run script at ./.dg-cached-runs/$BACKUP_NAME/dg_cached_run.sh"
    ./.dg-cached-runs/$BACKUP_NAME/dg_cached_run.sh
fi

# Save the name of the backupdir in the local folder as $BACKUP_DIR.cached
mkdir -p ./.dg-cached-runs
mkdir -p ./.dg-cached-runs/$BACKUP_NAME

# export PDT_AGENT_SECRET=$(grep "PDT_AGENT_SECRET" $BACKUP_DIR/k8s_describe_pods.txt | head -n 1 | cut -d "'" -f 2)

# export LITELLM_KEY='sk-PhMkn-ug9XmXSGLryqENvA'
# export AIXCC_LITELLM_HOSTNAME='http://lite.tianleyu.com:4000'
export AIXCC_LITELLM_HOSTNAME="http://wiseau.seclab.cs.ucsb.edu:666/"
export LITELLM_KEY="sk-artiphishell-da-best!!!"
export USE_LLM_API=1

RESTART_SERVICES="${RESTART_SERVICES:-False}"
TASK_NAME=discovery_guy_from_bypass_request
PRIMARY_KEY_REPO=patch_bypass_request

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

function get_codeql_block(){
    local key=$1
    shift 1
    get_blob_repo_entry "$BACKUP_DIR/codeql_build${key}" $@.tar.gz
}

export PATCH_BYPASS_REQUEST_ID="${PRIMARY_KEY_ID}"
export PATCH_BYPASS_META=$(get_meta discovery_guy_from_bypass_request.patch_bypass_request ${PATCH_BYPASS_REQUEST_ID})
export BUILD_REQUEST_ID=$(lookup_meta_key "$PATCH_BYPASS_META" ".build_request_id")
export HARNESS_ID=$(lookup_meta_key "$PATCH_BYPASS_META" ".harness_id")
export HARNESS_INFO_FILE="${HARNESS_INFO_FILE:-$(get_meta grammar_guy_fuzz.project_harness_metadata_fp/ ${HARNESS_ID})}"
export HARNESS_NAME=$(lookup_meta_key "$HARNESS_INFO_FILE" ".cp_harness_name")
export PROJECT_ID=${PROJECT_ID:-$(lookup_meta_key "$HARNESS_INFO_FILE" ".project_id")}
export CRS_TASK_ANALYSIS_SOURCE=$(get_fs "kumushi.crs_tasks_analysis_source" "$PROJECT_ID")
export BUILD_CONFIGURATION_ID=$(lookup_meta_key "$HARNESS_INFO_FILE" ".build_configuration_id")
export PROJECT_NAME=$(lookup_meta_key "$HARNESS_INFO_FILE" ".project_name")
export PROJECT_METADATA_PATH=$(get_meta "poiguy.project_metadata_path" "$PROJECT_ID")
export LANG=$(lookup_meta_key $(get_meta "poiguy.project_metadata_path" "$PROJECT_ID" ".language") ".language")
export TARGET_METADATA=$(get_meta "poiguy.project_metadata_path" "$PROJECT_ID")
export OSS_FUZZ_REPO_PATH=$(get_fs "pipeline_input.oss_fuzz_repo" "$PROJECT_ID")
export SANITIZER=$(lookup_meta_key "$PATCH_BYPASS_META" ".sanitizer_name")
export PATCHED_BUILD_ARTIFACT=$(get_fs "discovery_guy_from_bypass_request.patched_artifact" ${BUILD_REQUEST_ID})
export PATCH_ID=$(lookup_meta_key "$PATCH_BYPASS_META" ".patch_id")
# export MITIGATED_POI_REPORT_ID=$(lookup_meta_key "$PATCH_BYPASS_META" ".mitigated_poi_report_id")
# export POIS=$(get_blob "poiguy.poi_report" "$MITIGATED_POI_REPORT_ID")
# export CRASHING_INPUT=$(get_blob discovery_guy_from_bypass_request.crashing_input_path ${MITIGATED_POI_REPORT_ID})
export TARGET_SOURCE_FOLDER=$(get_fs analyze_target.project_analysis_sources ${PROJECT_ID})
export AGGREGATED_HARNESS_INFO=$(get_meta "harness_info_splitter.target_split_metadata_path" ${PROJECT_ID})
export HARNESS_ID=$(lookup_meta_key "$PATCH_BYPASS_META" ".harness_id")
export DEBUG_BUILD_ARTIFACT=$(get_fs "discovery_guy_from_bypass_request.debug_build_artifacts" ${BUILD_CONFIGURATION_ID})
export CODEQL_DB_PATH=$(get_codeql_block ".codeql_database_path" "$PROJECT_ID")
export ANALYSIS_GRAPH_PASSWORD=$(grep -m1 "ANALYSIS_GRAPH_BOLT_URL" $BACKUP_DIR/pydatatask_agent.logs/1 | grep -oP 'ANALYSIS_GRAPH_BOLT_URL=bolt://[^:]+:\K[^@]+' |  cut -d' ' -f1)
export ANALYSIS_GRAPH_BOLT_URL="bolt://neo4j:helloworldpdt@172.17.0.6:7687"
export CODEQL_SERVER_URL='http://172.17.0.1:4000'
export FUNC_RESOLVER_URL='http://172.17.0.1:4033'
export SERVICE_FOLDER=$(echo $SERVICE_FOLDER_COMMAND | bash)
export CRASH_DIR_PASS_TO_POV=$(mktemp -d /tmp/crash_dir_pass_to_pov.XXXXXX)
export CRASH_METADATA_DIR_PASS_TO_POV=$(mktemp -d /tmp/crash_metadata_dir_pass_to_pov.XXXXXX)

mkdir -p /shared/discoveryguy/bypasses/ || true
# Now create a temporary directory in the bypasses
export BYPASS_RESULT_DIR=$(mktemp -d -p /shared/discoveryguy/bypasses/)

# Ask the user if they want to restart the services
echo "Do you want to restart the services? If you are testing a new target you MUST DO IT (y/n)"
read -r RESTART_SERVICES_INPUT
if [ "$RESTART_SERVICES_INPUT" = "y" ]; then
    RESTART_SERVICES=True
else
    RESTART_SERVICES=False
fi

# Check if the RESTART_SERVICES variable is set to True
if [ "$RESTART_SERVICES" = "True" ]; then

    echo "=== Restarting services... ==="

    pushd $SERVICE_FOLDER/codeql_server
        docker compose down || true
        docker compose up -d
    popd

    echo "Press any key when the codeql server comes up... (docker ps && docker logs <CONTAINER_ID>)"
    read whatever

    echo "init codeql db"
    export CODEQL_ZIP_FOLDER=$(get_fs codeql_build.codeql_database_path/ ${PROJECT_ID})
    echo "CODEQL_ZIP_FOLDER: $CODEQL_ZIP_FOLDER"

    # Check if $CODEQL_ZIP_FOLDER/sss-codeql-database.zip exists
    if [ ! -f "$CODEQL_ZIP_FOLDER/sss-codeql-database.zip" ]; then
        echo "File $CODEQL_ZIP_FOLDER/sss-codeql-database.zip does not exist"
        exit 1
    fi

    codeql-upload-db --cp_name $PROJECT_NAME --project_id $PROJECT_ID --db_file $CODEQL_ZIP_FOLDER/sss-codeql-database.zip --language $LANG || true

    echo "Initializing the analysis-graph database..."
    NEO4J_DB=$BACKUP_DIR/analysisgraph_1.tar.gz
    # Check if the file exists
    if [ ! -f "$NEO4J_DB" ]; then
        echo "File $NEO4J_DB does not exist. Plese wget it from the backup URL. e.g., wget https://aixcc-diskman.adamdoupe.com/iKbr6hfymftxL7pr3FEX/pipeline-backup/nginx/14422031803/analysisgraph.tar.gz"
        exit 1
    fi

    cp $NEO4J_DB $SERVICE_FOLDER/analysis_graph/analysisgraph.tar.gz

    pushd $SERVICE_FOLDER/analysis_graph
        docker compose down || true
        rm -rf neo4j_db || true
        tar -xf analysisgraph.tar.gz
        mv analysisgraph/var/lib/neo4j neo4j_db
        ls neo4j_db/labs/
        # Detect if we have apoc-2025.04.0-core.jar or apoc-2025.03.0-core.jar
        if [ -f neo4j_db/labs/apoc-2025.04.0-core.jar ]; then
            cp neo4j_db/labs/apoc-2025.04.0-core.jar neo4j_db/plugins/
        elif [ -f neo4j_db/labs/apoc-2025.03.0-core.jar ]; then
            cp neo4j_db/labs/apoc-2025.03.0-core.jar neo4j_db/plugins/
        elif [ -f neo4j_db/labs/apoc-2025.05.0-core.jar ]; then
            cp neo4j_db/labs/apoc-2025.05.0-core.jar neo4j_db/plugins/
        elif [ -f neo4j_db/labs/apoc-2025.05.1-core.jar ]; then
            cp neo4j_db/labs/apoc-2025.05.1-core.jar neo4j_db/plugins/
        else
            echo "No apoc jar found, aborting"
            exit 1
        fi

        # Just to avoid stupid permission errors...
        chmod -R 777 neo4j_db
        docker compose up -d || true
    popd

    echo "Press any key when the analysis-graph comes up...(docker ps && docker logs <CONTAINER_ID>)"
    # Read input from user
    read whatever

fi

# Clean the fuzzer_sync (ONLY LOCALLY!)
rm -rf /shared/fuzzer_sync/

# If you want, for faster debugging
# echo "Starting a remote function resolver for faster debugging..."
# function-resolver-upload-backup $BACKUP_DIR

./run_from_bypass.sh