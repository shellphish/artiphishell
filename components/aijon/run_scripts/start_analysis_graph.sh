#!/bin/bash

set -eux
set -o pipefail

source /shellphish/libs/test-utils/backup-handling-utils.sh

BACKUP_DIR="${1:-}"
export SERVICE_FOLDER=$(echo $SERVICE_FOLDER_COMMAND | bash)

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


TAR_NAME="analysisgraph_1.tar.gz"
if [ ! -f $BACKUP_DIR/$TAR_NAME ]; then
    TAR_NAME="analysisgraph.tar.gz"
    if [ ! -f $BACKUP_DIR/$TAR_NAME ]; then
        echo "No analysis graph found"
        exit 1
    fi
fi

AG_HASH=$(md5sum $BACKUP_DIR/$TAR_NAME | awk '{print $1}')

if [ -f "$SERVICE_FOLDER/analysis_graph/$TAR_NAME" ]; then
    OLD_HASH=$(md5sum $SERVICE_FOLDER/analysis_graph/$TAR_NAME | awk '{print $1}')
    if [ "$AG_HASH" == "$OLD_HASH" ]; then
        echo "[*] Analysis graph tarball is already up to date."
        echo "Force update (Y/n)?"
        read -r FORCE_UPDATE
        if [[ "$FORCE_UPDATE" =~ ^[Yy]$ ]]; then
            echo "[*] Forcing update of analysis graph tarball..."
        else
            echo "[*] Skipping update of analysis graph tarball."
            exit 0
        fi
    else
        echo "[*] Analysis graph tarball has changed, updating..."
    fi
fi

# Get the analysis graph up and running
(
    echo "[*] Initializing the analysis-graph database..."
    docker pull neo4j:latest
    NEO4J_DB=$BACKUP_DIR/$TAR_NAME
    # Check if the file exists
    if [ ! -f "$NEO4J_DB" ]; then
        echo "[!] File $NEO4J_DB does not exist. Plese wget it from the backup URL. e.g., wget https://aixcc-diskman.adamdoupe.com/iKbr6hfymftxL7pr3FEX/pipeline-backup/nginx/14422031803/$TAR_NAME"
        exit 1
    fi

    cp $NEO4J_DB $SERVICE_FOLDER/analysis_graph/$TAR_NAME

    pushd $SERVICE_FOLDER/analysis_graph
        docker compose down || true
        rm -rf neo4j_db || true
        tar -xf $TAR_NAME
        mv analysisgraph/var/lib/neo4j neo4j_db
        ls -l neo4j_db/labs/

        # Detect if we have apoc-2025.04.0-core.jar or apoc-2025.03.0-core.jar
        if [ -f neo4j_db/labs/apoc-2025.*-core.jar ]; then
            cp neo4j_db/labs/apoc-2025.*-core.jar neo4j_db/plugins/
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
)
