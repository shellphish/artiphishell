#!/bin/bash

set -eu

# This script MUST be run from the root of the project, NOT from the 
# devcontainer. Thus, we check if the full path of the local folder
# contains your username.
CURR_USERNAME=$(whoami)
if [[ $PWD == *"$CURR_USERNAME"* ]]; then
    echo "Running from the root of the project"
else
    echo "Please run this script outside the devcontainer"
    exit 1
fi

# Check if in the current folder we have the _run-pdt.sh script
if [ ! -f _run-pdt.sh ]; then
    echo "Please run this script from the local_test/pdt folder"
    exit 1
fi


echo "Updating pydatatask..."
# Reinstall latest pdt just in case
pushd ../../../../libs/pydatatask/
    pip install -e .
popd

source ../../../../libs/test-utils/backup-handling-utils.sh

export LOCAL_RUN=True
BACKUP_DIR="${1:-}"
export BACKUP_DIR

PRIMARY_KEY_ID="${2:-}"
POI_REPORTS_DIR="${POI_REPORTS_DIR:-}"

BACKUP_NAME=$(basename "$BACKUP_DIR")
export BACKUP_NAME


# Set permissions to the backup directory
sudo chown -R $CURR_USERNAME:$CURR_USERNAME "$BACKUP_DIR"
sudo chmod -R 777 "$BACKUP_DIR/"

export AIXCC_LITELLM_HOSTNAME="http://wiseau.seclab.cs.ucsb.edu:666/"
export LITELLM_KEY="sk-artiphishell-da-best!!!"
export USE_LLM_API=1

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
    else
        echo "Using ${PRIMARY_KEY_REPO}: ${PRIMARY_KEY_ID}"
    fi
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


export ANALYSIS_GRAPH_PASSWORD=$(grep -m1 "ANALYSIS_GRAPH_BOLT_URL" $BACKUP_DIR/pydatatask_agent.logs/1 | grep -oP 'ANALYSIS_GRAPH_BOLT_URL=bolt://[^:]+:\K[^@]+' |  cut -d' ' -f1)

export LANG="c"

export SERVICE_FOLDER="../../../../services"



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

    echo "Initializing the analysis-graph database..."
    NEO4J_DB=$BACKUP_DIR/analysisgraph.tar.gz
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


# ask the user for the analysis graph url
docker ps | grep neo4j || true
echo "Please enter the analysis graph url"
read -r ANALYSIS_GRAPH_URL

export ANALYSIS_GRAPH_BOLT_URL="bolt://neo4j:$ANALYSIS_GRAPH_PASSWORD@$ANALYSIS_GRAPH_URL:7687"
echo "ANALYSISGRAPH AT $ANALYSIS_GRAPH_BOLT_URL"


# Ask the user if they want to rebuild the base image

echo "Do you want to rebuild the base image? (y/n)"
read -r REBUILD_BASE_IMAGE_INPUT
if [ "$REBUILD_BASE_IMAGE_INPUT" = "y" ]; then
    echo "********************************"
    echo "Rebuilding the CRS base image..."
    echo "********************************"
    pushd ../../../../local_run/
        ./rebuild_base_images.sh
    popd
fi


echo "********************************"
echo "Rebuilding covguy container....."
echo "********************************"
pushd ../../
    ls -la
    docker build -t aixcc-coverageguy . --no-cache
popd 

./_run-pdt.sh