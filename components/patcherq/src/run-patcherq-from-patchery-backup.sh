#!/bin/bash


source /shellphish/libs/test-utils/backup-handling-utils.sh

INVARIANTS="${INVARIANTS:-}"
BACKUP_DIR="${1:-}"
PATCH_REQUEST_ID="${2:-}"
OUTPUT_DIR="${OUTPUT_DIR:-}"

export AIXCC_LITELLM_HOSTNAME="http://wiseau.seclab.cs.ucsb.edu:666"
export LITELLM_KEY="sk-artiphishell-da-best!!!"
export LOCAL_RUN="${LOCAL_RUN:-True}"
export PATCHERQ_MODE="PATCH"

PATCHERY_TASK_NAME=patchery
PATCHERG_TASK_NAME=patcherg
PRIMARY_KEY_REPO=poi_report

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

if [ -z "${PATCH_REQUEST_ID}" ]; then
    echo "Available PATCH_REQUESTS to run: "
    for f in "${BACKUP_DIR}/patcherg.patch_requests_meta"/*; do
        echo "$(basename "${f%.yaml}")"
    done
    echo "Which PATCH_REQUEST_ID would you like to run?"
    read -r PATCH_REQUEST_ID

    # ensure that the PATCH_REQUESTS exists
    if [ ! -f "${BACKUP_DIR}/patcherg.patch_requests_meta/${PATCH_REQUEST_ID}.yaml" ]; then
        echo "Invalid PATCH_REQUEST_ID: ${PATCH_REQUEST_ID}"
        exit 1
    fi
fi


function get_meta() {
    local key=$1
    shift 1
    get_metadata_repo_entry "$BACKUP_DIR/${PATCHERY_TASK_NAME}${key}" $@
}

function get_patch_request_meta() {
    local key=$1
    shift 1
    get_metadata_repo_entry "$BACKUP_DIR/${PATCHERG_TASK_NAME}${key}" $@
}


function get_fs() {
    local key=$1
    shift 1
    get_filesystem_repo_entry "$BACKUP_DIR/${PATCHERY_TASK_NAME}${key}" $@
}
get_coverage_fs() {
    local key=$1
    shift 1
    get_filesystem_repo_entry "$BACKUP_DIR/${key}" $@
}

function get_blob() {
    local key=$1
    shift 1
    get_blob_repo_entry "$BACKUP_DIR/${PATCHERY_TASK_NAME}${key}" $@
}

function get_patch_meta_blob() {
    local key=$1
    shift 1
    get_blob_repo_entry "$BACKUP_DIR/${PATCHERY_TASK_NAME}${key}" $@.yaml
}

function get_inv_blob() {
    local key=$1
    shift 1
    echo "Looking for $BACKUP_DIR/${PATCHERY_INV_TASK_NAME}${key}/$@.yaml" > /dev/stderr
    if [ ! -f "$BACKUP_DIR/${PATCHERY_INV_TASK_NAME}${key}/$@.yaml" ]; then
        echo "" > /dev/stderr
    else
        get_blob_repo_entry "$BACKUP_DIR/${PATCHERY_INV_TASK_NAME}${key}" $@.yaml
    fi
}

function lookup_meta_key() {
    get_metadata_key $@
}

function get_new_blob() {
    local key=$1
    shift 1
    get_blob_repo_entry "$BACKUP_DIR/generate_full_function_index${key}" $@
}

function get_patch_meta_blob() {
    local key=$1
    shift 1
    get_blob_repo_entry "$BACKUP_DIR/patcherg${key}" $@.yaml
}


function get_dyva_blob() {
    local key=$1
    shift 1
    get_blob_repo_entry "$BACKUP_DIR/dyva_agent${key}" $@.yaml
}

function get_codeql_block(){
    local key=$1
    shift 1
    get_blob_repo_entry "$BACKUP_DIR/codeql_build${key}" $@.tar.gz
}

function get_codeql_build_meta(){
    local key=$1
    shift 1
    get_blob_repo_entry "$BACKUP_DIR/codeql_build${key}" $@.yaml
}

export PATCH_REQUEST_ID="${PATCH_REQUEST_ID}"
export PATCH_REQUEST_META=$(get_patch_request_meta ".patch_requests_meta" "$PATCH_REQUEST_ID")
export POI_REPORT_ID=$(lookup_meta_key "$PATCH_REQUEST_META" ".poi_report_id")
export POI_REPORT_PATH=$(get_meta ".poi_report_meta" "$POI_REPORT_ID")
export BUILD_CONFIGURATION_ID=$(lookup_meta_key "$POI_REPORT_PATH" ".build_configuration_id")
export PROJECT_ID=$(lookup_meta_key "$POI_REPORT_PATH" ".project_id")
export CRS_TASK_ANALYSIS_SOURCE=$(get_fs ".crs_tasks_analysis_source" "$PROJECT_ID")
export CRASHING_INPUT_PATH=$(get_blob ".crashing_input_path" "$POI_REPORT_ID")
# export SANITIZER_STRING=$(lookup_meta_key "$POI_REPORT_PATH" '.consistent_sanitizers[-1]')
export POI_REPORT=$(get_blob ".poi_report" "$POI_REPORT_ID")
export PROJECT_NAME=$(lookup_meta_key "$POI_REPORT_PATH" ".project_name")
export PROJECT_METADATA=$(get_meta ".project_metadata" "$PROJECT_ID")
export PROJECT_LANGUAGE=$(lookup_meta_key "$PROJECT_METADATA" ".language")

# if PROJECT_LANGUAGE is c++, set it to c
if [ "$PROJECT_LANGUAGE" == "c++" ]; then
    export PROJECT_LANGUAGE="c"
fi

export OSS_FUZZ_REPO=$(get_fs ".oss_fuzz_repo" "$PROJECT_ID")
export FULL_FUNCTIONS_JSONS_DIR=$(get_fs ".full_functions_jsons_dir" "$PROJECT_ID")
export FULL_FUNCTIONS_INDEX=$(get_blob ".full_functions_index" "$PROJECT_ID")
export FUNCTIONS_BY_FILE_INDEX=$(get_new_blob ".functions_by_file_index_json" "$PROJECT_ID")
export DYVA_REPORT=$(get_dyva_blob ".dyva_report" "$PATCH_REQUEST_ID")

if [ -z "${OUTPUT_DIR}" ]; then
    export OUTPUT_DIR=$(mktemp -d)
    echo "Created output dir: $OUTPUT_DIR"
fi

export PATCH_OUTPUT_PATH="${OUTPUT_DIR}/patch_out" # {{out_patch | shquote}}
export PATCH_METADATA_OUTPUT_PATH="${OUTPUT_DIR}/patch_meta_out" # {{out_patch.cokeyed_dirs.meta | shquote}}
export SARIF_OUTPUT_PATH="${OUTPUT_DIR}/sarif_out" # {{out_sarif | shquote}}
export BYPASS_REQUEST_PATH="${OUTPUT_DIR}/bypass_request_out"

export PATCHED_ARTIFACTS_DIR="${OUTPUT_DIR}/patched_artifacts_dir"
export PATCHED_ARTIFACTS_DIR_LOCK="${OUTPUT_DIR}/patched_artifacts_dir_lock"

export CRS_MODE=$(lookup_meta_key $(get_meta ".crs_task_meta" "$PROJECT_ID") ".type")
if [ "$CRS_MODE" == "delta" ]; then
    export DIFF_FILE=$(get_blob_repo_entry "$BACKUP_DIR/patcherq_delta.crs_task_diff" $PROJECT_ID)
    export CHANGED_FUNCTIONS_INDEX=$(get_blob_repo_entry "$BACKUP_DIR/patcherq_delta.commit_functions_index" "$PROJECT_ID")
    export CHANGED_FUNCTIONS_JSONS_DIR=$(get_filesystem_repo_entry "$BACKUP_DIR/patcherq_delta.commit_functions_jsons_dir" "$PROJECT_ID")
fi

mkdir -p $OUTPUT_DIR
mkdir -p $OUTPUT_DIR/patch_out
mkdir -p $OUTPUT_DIR/patch_meta_out
mkdir -p $OUTPUT_DIR/sarif_out
mkdir -p $OUTPUT_DIR/bypass_request_out

# Fake the pdt directory
mkdir -p $OUTPUT_DIR/patched_artifacts_dir
mkdir -p $OUTPUT_DIR/patched_artifacts_dir_lock

export CODEQL_DB_PATH=$(get_codeql_block ".codeql_database_path" "$PROJECT_ID")
export CODEQL_DB_READY=$(get_codeql_build_meta ".codeql_db_ready" "$PROJECT_ID")
export SERVICE_FOLDER=$(echo $SERVICE_FOLDER_COMMAND | bash)
export ANALYSIS_GRAPH_PASSWORD=$(grep -m1 "ANALYSIS_GRAPH_BOLT_URL" $BACKUP_DIR/pydatatask_agent.logs/1 | grep -oP 'ANALYSIS_GRAPH_BOLT_URL=bolt://[^:]+:\K[^@]+' |  cut -d' ' -f1)
export ANALYSIS_GRAPH_BOLT_URL="bolt://neo4j:helloworldpdt@172.17.0.2:7687"

# ask the user if the codeql server is at http://172.17.0.17:4000
if [ -z "${CODEQL_SERVER_URL}" ]; then
    echo "**************************************************************************************"
    echo "**************************************************************************************"
    echo "Is the codeql server at http://172.17.0.3:4000?"
    echo "  - check with docker ps and then docker inspect the aixcc-codeql-server to see the ip"
    echo "**************************************************************************************"
    echo "**************************************************************************************"
    echo " [y\n] (default: n)"
    read -r CODEQL_SERVER_URL_ANSWER
    if [ "$CODEQL_SERVER_URL_ANSWER" == "y" ]; then
        export CODEQL_SERVER_URL='http://172.17.0.3:4000'
    else
        echo "Please enter the codeql server url:"
        read -r CODEQL_SERVER_URL
        export CODEQL_SERVER_URL
    fi
fi

# Delete the old patcherq logs
rm -rf /tmp/stats/*

# Ask the user if they want to restart the analysis graph 
echo "Do you want to restart the analysis graph? If you are testing a new target you MUST DO IT (y/n)"
read -r RESTART_SERVICES_INPUT
if [ "$RESTART_SERVICES_INPUT" = "y" ]; then
    RESTART_GRAPH=True
else
    RESTART_GRAPH=False
fi

if [ "$RESTART_GRAPH" = "True" ]; then
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
            ls -l neo4j_db/labs/
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

./run-patcherq.sh
