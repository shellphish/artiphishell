#!/bin/bash

set -eu
source /shellphish/libs/test-utils/backup-handling-utils.sh

BACKUP_DIR="${1:-}"
PRIMARY_KEY_ID="${2:-}"
LANGUAGE="${3:-}"

export USE_LLM_API=1
export LITELLM_KEY=sk-artiphishell-da-best!!!
export CODEQL_SERVER_URL='http://172.17.0.1:4000'
export FUNC_RESOLVER_URL='http://172.17.0.1:4033'
RESTART_SERVICES="${RESTART_SERVICES:-False}"
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

export PROJECT_NAME=$(lookup_meta_key "$HARNESS_INFO_FILE" ".project_name")
export SERVICE_FOLDER=$(echo $SERVICE_FOLDER_COMMAND | bash)
# export LANGUAGE=$(lookup_meta_key "$HARNESS_INFO_FILE" ".language")
export DIFF_FILE=$(get_blob "diff_mode_create_analysis_source.crs_task_diff" "$PROJECT_ID")

export COMMIT_FUNCTIONS_INDEX=$(get_blob generate_commit_function_index.target_functions_index ${PROJECT_ID})
export FUNCTIONS_INDEX=$(get_blob grammar_guy_fuzz.functions_index ${PROJECT_ID})
export FUNCTIONS_JSONS_DIR=$(get_fs grammar_guy_fuzz.functions_jsons_dir ${PROJECT_ID})
echo "Which language is the project? (c, c++ or jvm.)"
read -r LANGUAGE

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
    export CODEQL_BASE_ZIP_FOLDER=$(get_fs codeql_build_base.codeql_database_path/ ${PROJECT_ID})
    echo "CODEQL_ZIP_FOLDER: $CODEQL_ZIP_FOLDER"

    # Check if $CODEQL_ZIP_FOLDER/sss-codeql-database.zip exists
    if [ ! -f "$CODEQL_ZIP_FOLDER/sss-codeql-database.zip" ]; then
        echo "File $CODEQL_ZIP_FOLDER/sss-codeql-database.zip does not exist"
        exit 1
    fi

    codeql-upload-db --cp_name $PROJECT_NAME --project_id $PROJECT_ID --db_file $CODEQL_ZIP_FOLDER/sss-codeql-database.zip --language $LANGUAGE || true
    codeql-upload-db --cp_name $PROJECT_NAME --project_id ${PROJECT_ID}-base --db_file $CODEQL_BASE_ZIP_FOLDER/sss-codeql-database.zip --language $LANGUAGE || true

fi

rm -rf /tmp/stats/*

export SERVICE_FOLDER=$(echo $SERVICE_FOLDER_COMMAND | bash)
export ANALYSIS_GRAPH_PASSWORD=$(grep -m1 "ANALYSIS_GRAPH_BOLT_URL" $BACKUP_DIR/pydatatask_agent.logs/1 | grep -oP 'ANALYSIS_GRAPH_BOLT_URL=bolt://[^:]+:\K[^@]+' |  cut -d' ' -f1)
export ANALYSIS_GRAPH_BOLT_URL="bolt://neo4j:$ANALYSIS_GRAPH_PASSWORD@172.17.0.3:7687"

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


echo "Running diffguy..."

python3 main.py \
        --name  $PROJECT_NAME\
        --language $LANGUAGE\
        --id-before "$PROJECT_ID-base" \
        --id-after "$PROJECT_ID" \
        --query-path "/shellphish/diffguy/custom" \
        --save-path "/shellphish/diffguy/results"\
        --diff-mode all \
        --run-mode local
