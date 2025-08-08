#!/bin/bash

set -eux

source /shellphish/libs/test-utils/backup-handling-utils.sh

BACKUP_DIR="${1:-}"
PRIMARY_KEY_ID="${2:-}"
POI_REPORTS_DIR="${POI_REPORTS_DIR:-}"

export LITELLM_KEY='sk-artiphishell-da-best!!!'
export AIXCC_LITELLM_HOSTNAME='http://wiseau.seclab.cs.ucsb.edu:666'
export USE_LLM_API="1"
export DELTA_MODE="${DELTA_MODE:-0}"

export TASK_NAME=grammaroomba
export PRIMARY_KEY_REPO=project_harness_only_metadatas_dir
export REPLICA_ID=${REPLICA_ID:-0}
PRELIMINARY_BACKUP_TASK_NAME=harness_info_splitter

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
    for f in "${BACKUP_DIR}/${PRELIMINARY_BACKUP_TASK_NAME}.${PRIMARY_KEY_REPO}"/*; do
        echo "$(basename "${f%.yaml}")"
    done
    echo "Which ${PRIMARY_KEY_REPO}s would you like to run?"
    read -r PRIMARY_KEY_ID

    # ensure that the PRIMARY_KEY exists
    if [ ! -f "${BACKUP_DIR}/${PRELIMINARY_BACKUP_TASK_NAME}.${PRIMARY_KEY_REPO}/${PRIMARY_KEY_ID}.yaml" ]; then
        echo "Invalid ${PRIMARY_KEY_REPO}: ${PRIMARY_KEY_ID}"
        exit 1
    fi
fi

# if the VDS_RECORD_ID somehow does not exist, then exit
echo "$BACKUP_DIR"
if [ ! -f "${BACKUP_DIR}/${PRELIMINARY_BACKUP_TASK_NAME}.${PRIMARY_KEY_REPO}/${PRIMARY_KEY_ID}.yaml" ]; then
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

if [ -z "${OUTPUT_DIR:-}" ]; then
    export OUTPUT_DIR=$(mktemp -d)/
    echo "Created output dir: $POI_REPORTS_DIR"
fi

export SEEDS_TO_TRIAGE_DIR="${OUTPUT_DIR}/seeds_to_triage"
export EVENTS_DIR="${OUTPUT_DIR}/events"
export DELTA_MODE="${DELTA_MODE:-0}"
mkdir -p "${SEEDS_TO_TRIAGE_DIR}" "${EVENTS_DIR}"


echo "Using harness info file: ${PRIMARY_KEY_ID}"
export ANALYSIS_GRAPH_PASSWORD=$(grep -m1 "ANALYSIS_GRAPH_BOLT_URL" $BACKUP_DIR/pydatatask_agent.logs/1 | grep -oP 'ANALYSIS_GRAPH_BOLT_URL=bolt://[^:]+:\K[^@]+' |  cut -d' ' -f1)
export ANALYSIS_GRAPH_BOLT_URL="bolt://neo4j:$ANALYSIS_GRAPH_PASSWORD@172.17.0.2:7687"
export SERVICE_FOLDER=$(echo $SERVICE_FOLDER_COMMAND | bash)
export JOB_ID="${PRIMARY_KEY_ID}"
export PROJECT_HARNESS_METADATA_ID="${PRIMARY_KEY_ID}"
export PROJECT_HARNESS_METADATA_FILE=$(get_meta harness_info_splitter.project_harness_only_metadatas_dir "${PRIMARY_KEY_ID}")
export PROJECT_ID=${PROJECT_ID:-$(lookup_meta_key "$PROJECT_HARNESS_METADATA_FILE" ".project_id")}
export BUILD_CONFIGURATION_ID=$(lookup_meta_key "$PROJECT_HARNESS_METADATA_FILE" ".build_configuration_id")
export COVERAGE_BUILD_ARTIFACT=$(get_fs grammar_agent_explore.coverage_build_artifact ${PROJECT_ID})
export PROJECT_NAME=$(lookup_meta_key "$PROJECT_HARNESS_METADATA_FILE" ".project_name")
export CP_HARNESS_NAME=$(lookup_meta_key "$PROJECT_HARNESS_METADATA_FILE" ".cp_harness_name")
export PROJECT_METADATA_FILE=$(get_meta grammar_guy_fuzz.project_metadata_path ${PROJECT_ID})
export TARGET_SPLIT_METADATA=$(get_meta harness_info_splitter.target_split_metadata_path "${PROJECT_ID}")
export FULL_FUNCTIONS_INDEX=$(get_blob grammar_guy_fuzz.functions_index ${PROJECT_ID})
export FULL_FUNCTIONS_JSONS_DIR=$(get_fs grammar_guy_fuzz.full_functions_jsons_dir ${PROJECT_ID})

set -x
if [ "x${DELTA_MODE:-}" = "x1" ]; then
    export COMMIT_FUNCTIONS_INDEX="$(get_blob generate_commit_function_index.target_functions_index ${PROJECT_ID})"
    export COMMIT_FUNCTIONS_JSONS_DIR="$(get_fs generate_commit_function_index.target_functions_jsons_dir ${PROJECT_ID})"
    echo "Running in delta mode, using commit functions index: ${COMMIT_FUNCTIONS_INDEX}"
fi

# Ask the user if they want to restart the services
echo "Do you want to restart the services? If you are testing a new target you MUST DO IT (y/n)"
read -r RESTART_SERVICES_INPUT
if [ "$RESTART_SERVICES_INPUT" = "y" ]; then
    RESTART_SERVICES=True
else
    RESTART_SERVICES=False
fi

if [ "$RESTART_SERVICES" = "True" ]; then

    echo "=== Restarting services... ==="
    echo "Initializing the analysis-graph database..."
    NEO4J_DB=$BACKUP_DIR/analysisgraph_1.tar.gz
    # Check if the file exists
    if [ ! -f "$NEO4J_DB" ]; then
        echo "File $NEO4J_DB does not exist. Plese wget it from the backup URL. e.g., wget https://aixcc-diskman.adamdoupe.com/iKbr6hfymftxL7pr3FEX/pipeline-backup/nginx/14422031803/analysisgraph.tar.gz"
        NEO4J_DB=$BACKUP_DIR/analysisgraph_1.tar.gz
        if [ ! -f "$NEO4J_DB" ]; then
            echo "File $NEO4J_DB does not exist. Plese wget it from the backup URL. e.g., wget https://aixcc-diskman.adamdoupe.com/iKbr6hfymftxL7pr3FEX/pipeline-backup/nginx/14422031803/analysisgraph_1.tar.gz"
            exit 1
        fi

    fi



    cp $NEO4J_DB $SERVICE_FOLDER/analysis_graph/analysisgraph.tar.gz

    pushd $SERVICE_FOLDER/analysis_graph
        docker compose down || true
        rm -rf neo4j_db || true
        tar -xf analysisgraph.tar.gz
        mv analysisgraph/var/lib/neo4j neo4j_db

        # Detect if we have apoc-2025.*-core.jar or apoc-2025.03.0-core.jar
        if [ -f neo4j_db/labs/apoc-2025.*-core.jar ]; then
            cp neo4j_db/labs/apoc-2025.*-core.jar neo4j_db/plugins/
        else
            echo "No apoc jar found, aborting"
        fi

        # Just to avoid stupid permission errors...
        chmod -R 777 neo4j_db
        docker compose up -d || true
    popd

    echo "Press any key when the analysis-graph comes up...(docker ps && docker logs <CONTAINER_ID>)"
    # Read input from user
    # read whatever
fi

echo "Running roomba with backup dir: ${BACKUP_DIR}"
echo "Exporting seeds to triage to: ${SEEDS_TO_TRIAGE_DIR}"
echo "Exporting events to: ${EVENTS_DIR}"

/shellphish/grammaroomba/run-roomba.sh