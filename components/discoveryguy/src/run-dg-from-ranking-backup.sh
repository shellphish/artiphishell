#!/bin/bash

set -eu

source /shellphish/libs/test-utils/backup-handling-utils.sh

export LOCAL_RUN=True
export DISCO_GUY_FROM="POIS"

export BACKUP_SEEDS_VAULT="/shared/dg_backup_seeds_vault"
export REPORT_DIR="/shared/reports"
mkdir -p $BACKUP_SEEDS_VAULT
mkdir -p $REPORT_DIR

BACKUP_DIR="${1:-}"
PRIMARY_KEY_ID="${2:-}"
POI_REPORTS_DIR="${POI_REPORTS_DIR:-}"

BACKUP_NAME=$(basename "$BACKUP_DIR")
export BACKUP_NAME
rm -rf /tmp/stats/*

# Save the name of the backupdir in the local folder as $BACKUP_DIR.cached
mkdir -p ./.dg-cached-runs
mkdir -p ./.dg-cached-runs/$BACKUP_NAME

# if the .$BACKUP_NAME exists, we can simply run the dg_cached_run.sh
if [ -f ./.dg-cached-runs/$BACKUP_NAME/dg_cached_run.sh ]; then
    echo "Running the cached run script at ./.dg-cached-runs/$BACKUP_NAME/dg_cached_run.sh"
    ./.dg-cached-runs/$BACKUP_NAME/dg_cached_run.sh
fi

# export PDT_AGENT_SECRET=$(grep "PDT_AGENT_SECRET" $BACKUP_DIR/k8s_describe_pods.txt | head -n 1 | cut -d "'" -f 2)

# export LITELLM_KEY='sk-PhMkn-ug9XmXSGLryqENvA'
# export AIXCC_LITELLM_HOSTNAME='http://lite.tianleyu.com:4000'
export AIXCC_LITELLM_HOSTNAME="http://wiseau.seclab.cs.ucsb.edu:666/"
export LITELLM_KEY="sk-artiphishell-da-best!!!"
export USE_LLM_API=1

RESTART_SERVICES="${RESTART_SERVICES:-False}"
TASK_NAME=grammar_guy_fuzz
PRIMARY_KEY_REPO=project_harness_metadata

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
    mkdir -p ./.dg-cached-runs/$BACKUP_NAME
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

export HARNESS_INFO_ID="${PRIMARY_KEY_ID}"
# export HARNESS_INFO_FILE="${HARNESS_INFO_FILE:-$(get_meta grammar_guy_fuzz.harness_info_fp/ ${HARNESS_INFO_ID})}"
export HARNESS_INFO_FILE="${HARNESS_INFO_FILE:-$(get_meta grammar_guy_fuzz.project_harness_metadata_fp/ ${HARNESS_INFO_ID})}"
export PROJECT_ID=${PROJECT_ID:-$(lookup_meta_key "$HARNESS_INFO_FILE" ".project_id")}
export CRS_TASK_ANALYSIS_SOURCE=$(get_fs "kumushi.crs_tasks_analysis_source" "$PROJECT_ID")
export PROJECT_NAME=$(lookup_meta_key "$HARNESS_INFO_FILE" ".project_name")
export PROJECT_METADATA_PATH=$(get_meta "poiguy.project_metadata_path" "$PROJECT_ID")
export OSS_FUZZ_REPO_PATH=$(get_fs "pipeline_input.oss_fuzz_repo" "$PROJECT_ID")
export PROJECT_LANGUAGE=$(lookup_meta_key $PROJECT_METADATA_PATH ".language")
# Get ALL the debug build artifacts available
export DEBUG_BUILD_ARTIFACTS=$(get_fs debug_build.debug_build_artifacts "/")

echo "****** EXTRACTING BUILD ARTIFACTS ******"
# Iterate over all the files in the DEBUG_BUILD_ARTIFACTS directory, if the file is a .tar.gz
# I want to extract it in a folder named after the file (without the .tar.gz) and then, delete the .tar.gz file.

# Check if directory exists
if [ ! -d "$DEBUG_BUILD_ARTIFACTS" ]; then
    echo "Error: Directory $DEBUG_BUILD_ARTIFACTS does not exist"
    exit 1
fi

# Change to the DEBUG_BUILD_ARTIFACTS directory
pushd "$DEBUG_BUILD_ARTIFACTS" > /dev/null || exit 1

# Iterate over all .tar.gz files in the directory
for tarfile in $(ls *.tar.gz); do
    # Check if any .tar.gz files exist (handle case where glob doesn't match)
    if [ ! -f "$tarfile" ]; then

        # if we have a sentinel we break (we extracted them before)
        if [ -f ".extracted" ]; then
            echo "All .tar.gz files have been processed."
            break
        else
            echo "No .tar.gz files found in $DEBUG_BUILD_ARTIFACTS"
            exit 1
        fi
    fi

    # Extract filename without .tar.gz extension
    folder_name="${tarfile%.tar.gz}"

    echo "Processing $tarfile..."
    echo "  -> Extracting to folder: $folder_name"

    # Create the folder if it doesn't exist
    mkdir -p "$folder_name"

    # Check file type and extract accordingly
    file_type=$(file "$tarfile")
    echo "  -> File type: $file_type"

    extracted=false

    # Try different extraction methods based on file type
    if echo "$file_type" | grep -q "gzip compressed"; then
        # Actually gzip compressed
        if tar -xzf "$tarfile" -C "$folder_name"; then
            extracted=true
        fi
    elif echo "$file_type" | grep -q "POSIX tar archive"; then
        # Uncompressed tar file
        if tar -xf "$tarfile" -C "$folder_name"; then
            extracted=true
        fi
    elif echo "$file_type" | grep -q "bzip2 compressed"; then
        # bzip2 compressed
        if tar -xjf "$tarfile" -C "$folder_name"; then
            extracted=true
        fi
    else
        # Try auto-detect (tar will figure it out)
        if tar -xaf "$tarfile" -C "$folder_name"; then
            extracted=true
        fi
    fi

    if [ "$extracted" = true ]; then
        echo "  -> Successfully extracted $tarfile"

        # # Delete the original tar.gz file
        # if rm "$tarfile"; then
        #     echo "  -> Deleted $tarfile"
        # else
        #     echo "  -> Warning: Failed to delete $tarfile"
        # fi
    else
        echo "  -> Error: Failed to extract $tarfile"
        # Don't delete the file if extraction failed
    fi

    echo ""

    # Drop a sentinel .extracted file in the folder
    touch "$folder_name/.extracted"
done

popd > /dev/null || exit 1

export TARGET_SOURCE_FOLDER=$(get_fs analyze_target.project_analysis_sources ${PROJECT_ID})
export FUNCTIONS_BY_FILE_INDEX=$(get_blob "generate_full_function_index.functions_by_file_index_json" "$PROJECT_ID")
export TARGET_METADATA=$(get_meta "poiguy.project_metadata_path" "$PROJECT_ID")
export FUNCTIONS_INDEX=$(get_blob grammar_guy_fuzz.functions_index ${PROJECT_ID})
export TARGET_FUNCTIONS_JSONS_DIR=$(get_fs grammar_guy_fuzz.functions_jsons_dir ${PROJECT_ID})
export AGGREGATED_HARNESS_INFO=$(get_meta "harness_info_splitter.target_split_metadata_path" ${PROJECT_ID})
export CODEQL_DB_PATH=$(get_codeql_block ".codeql_database_path" "$PROJECT_ID")
export ANALYSIS_GRAPH_PASSWORD=$(grep -m1 "ANALYSIS_GRAPH_BOLT_URL" $BACKUP_DIR/pydatatask_agent.logs/1 | grep -oP 'ANALYSIS_GRAPH_BOLT_URL=bolt://[^:]+:\K[^@]+' |  cut -d' ' -f1)
export ANALYSIS_GRAPH_BOLT_URL="bolt://neo4j:$ANALYSIS_GRAPH_PASSWORD@172.17.0.1:7687"
export CODEQL_SERVER_URL='http://172.17.0.1:4000'
export FUNC_RESOLVER_URL='http://172.17.0.1:4033'
export SERVICE_FOLDER=$(echo $SERVICE_FOLDER_COMMAND | bash)
export POIS=$(get_blob quickseed_codeql_query.discovery_vuln_reports ${PROJECT_ID})
export FUNC_RANKING=$(get_blob "code_swipe.codeswipe_rankings" ${PROJECT_ID})
export CRASH_DIR_PASS_TO_POV=$(mktemp -d /tmp/crash_dir_pass_to_pov.XXXXXX)
export CRASH_METADATA_DIR_PASS_TO_POV=$(mktemp -d /tmp/crash_metadata_dir_pass_to_pov.XXXXXX)
# if the environment variable is not set, ask the user
export DELTA_MODE="${DELTA_MODE:-}"
if [ -z "$DELTA_MODE" ]; then
    echo "Would you like to run in delta mode? (yes/no) [default: no]"
    read -r DELTA_MODE
    if [ "$DELTA_MODE" = "yes" ]; then
        echo "Running in delta mode (with diff info)"
        export DELTA_MODE=True
    else
        echo "Running in full mode (no diff info)"
        export DELTA_MODE=False
    fi
else
    echo "Running in delta mode..."
fi

if [ "$DELTA_MODE" = "True" ]; then
    # FIXME: I think this is wrong?
    export CHANGED_FUNCTIONS_JSONS_DIR=$(get_fs grammar_guy_fuzz.functions_jsons_dir ${PROJECT_ID})
    export CHANGED_FUNCTIONS_INDEX=$(get_blob generate_commit_function_index.target_functions_index ${PROJECT_ID})
    export DIFF_FILE=$(get_blob "diff_mode_create_analysis_source.crs_task_diff" "$PROJECT_ID")
else
    export CHANGED_FUNCTIONS_JSONS_DIR=""
    export CHANGED_FUNCTIONS_INDEX=""
    export DIFF_FILE=""
fi

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
    # read whatever

    echo "init codeql db"
    export CODEQL_ZIP_FOLDER=$(get_fs codeql_build.codeql_database_path/ ${PROJECT_ID})
    echo "CODEQL_ZIP_FOLDER: $CODEQL_ZIP_FOLDER"

    # Check if $CODEQL_ZIP_FOLDER/sss-codeql-database.zip exists
    if [ ! -f "$CODEQL_ZIP_FOLDER/sss-codeql-database.zip" ]; then
        echo "File $CODEQL_ZIP_FOLDER/sss-codeql-database.zip does not exist"
        exit 1
    fi

    codeql-upload-db --cp_name $PROJECT_NAME --project_id $PROJECT_ID --db_file $CODEQL_ZIP_FOLDER/sss-codeql-database.zip --language $PROJECT_LANGUAGE || true

    echo "Initializing the analysis-graph database..."
    NEO4J_DB=$BACKUP_DIR/analysisgraph.tar.gz
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

        # Detect if we have apoc-2025.04.0-core.jar or apoc-2025.03.0-core.jar
        if [ -f neo4j_db/labs/apoc-2025.04.0-core.jar ]; then
            cp neo4j_db/labs/apoc-2025.04.0-core.jar neo4j_db/plugins/
        elif [ -f neo4j_db/labs/apoc-2025.03.0-core.jar ]; then
            cp neo4j_db/labs/apoc-2025.03.0-core.jar neo4j_db/plugins/
        elif [ -f neo4j_db/labs/apoc-2025.05.0-core.jar ]; then
            cp neo4j_db/labs/apoc-2025.05.0-core.jar neo4j_db/plugins/
        else
            echo "No apoc jar found, aborting"
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


#./run_from_ranking_parallel.
# Ask the user if they want to run in parallel
echo "<<<Do you want to run in parallel? (y/n)>>>"
read -r RUN_IN_PARALLEL

if [ "$RUN_IN_PARALLEL" = "y" ]; then
    ./run_from_ranking_parallel.sh
elif [ "$RUN_IN_PARALLEL" = "n" ]; then
    ./run_from_ranking.sh
else
    echo "Invalid input, please enter y or n"
    exit 1
fi