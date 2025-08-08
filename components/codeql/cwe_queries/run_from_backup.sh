#!/bin/bash

set -eu
set -x

# source ../../../libs/test-utils/backup-handling-utils.sh
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

# Setup environment variables for the CWE query analysis
export PROJ_ID=$PRIMARY_KEY_ID
export PROJ_META=$(get_meta codeql_build.meta/ ${PRIMARY_KEY_ID})
export CRS_TASK_META=$(get_meta codeql_build.crs_task/ ${PRIMARY_KEY_ID})
export CP_NAME=$(lookup_meta_key "$CRS_TASK_META" ".project_name")
export LANG=$(lookup_meta_key "$PROJ_META" ".language")
export FUNC_RESOLVER_URL='http://172.17.0.1:4033'

# Set up analysis graph environment
echo "=== Analysis Graph Setup ==="
# export ANALYSIS_GRAPH_BOLT_URL='bolt://neo4j:helloworldpdt@172.17.0.1:7687'
export ANALYSIS_GRAPH_BOLT_URL='bolt://neo4j:helloworldpdt@localhost:7687'
echo "Analysis Graph URL: $ANALYSIS_GRAPH_BOLT_URL"

# Add analysis graph to Python path
export PYTHONPATH="${PYTHONPATH:-}:$(pwd)/../../../libs/analysis-graph/src"

# Set up output directories

export OUTPUT_BASE_DIR="$(pwd)/out/cwe_analysis_${PROJ_ID}/$(date +%Y%m%d_%H%M%S)"
export CODEQL_CWE_SARIF_REPORT_PATH="${OUTPUT_BASE_DIR}/codeql_cwe_sarif_report.json"
export CODEQL_CWE_REPORT_PATH="${OUTPUT_BASE_DIR}/codeql_cwe_report.json"

mkdir -p "${OUTPUT_BASE_DIR}"

echo "=== CodeQL Database Setup ==="
echo "Project: $CP_NAME"
echo "Project ID: $PROJ_ID"
echo "Language: $LANG"
echo "Output Directory: $OUTPUT_BASE_DIR"

# Initialize CodeQL databases
echo "Setting up CodeQL databases..."
export CODEQL_ZIP_FOLDER=$(get_fs codeql_build.codeql_database_path/ ${PROJ_ID})
export CODEQL_BUILDLESS_ZIP_FOLDER=$(get_fs codeql_build.codeql_database_path_buildless/ ${PROJ_ID})

# --------------------------------------------------------------
# Detect optional base CodeQL database produced by codeql_build_base
# --------------------------------------------------------------
BASE_CODEQL_REPO_DIR="codeql_build_base.codeql_database_path"
export HAS_BASE_DB=false
if [ -f "$BACKUP_DIR/${BASE_CODEQL_REPO_DIR}/${PROJ_ID}.tar.gz" ] || \
   [ -d "$BACKUP_DIR/${BASE_CODEQL_REPO_DIR}/${PROJ_ID}" ] ; then
    HAS_BASE_DB=true
    export CODEQL_BASE_ZIP_FOLDER=$(get_fs ${BASE_CODEQL_REPO_DIR}/ ${PROJ_ID})
    echo "Found base CodeQL database at: $CODEQL_BASE_ZIP_FOLDER"
    export CODEQL_BASE_BUILDLESS_ZIP_FOLDER=$(get_fs ${BASE_CODEQL_REPO_DIR}_buildless/ ${PROJ_ID})
    echo "Found base buildless CodeQL database at: $CODEQL_BASE_BUILDLESS_ZIP_FOLDER"

    # Unzip the base database
    export CODEQL_BASE_DB_PATH=$(mktemp -d /tmp/cqlcweq-base-cqldb-XXXXXX)
    unzip -q "$CODEQL_BASE_ZIP_FOLDER/sss-codeql-database.zip" -d "$CODEQL_BASE_DB_PATH"
    export CODEQL_BASE_DATABASE_PATH="$CODEQL_BASE_DB_PATH/.sss-codeql-database"

    # Output paths
    export CODEQL_CWE_SARIF_REPORT_BASE_PATH="${OUTPUT_BASE_DIR}/codeql_cwe_sarif_report_base.json"
    export CODEQL_CWE_REPORT_BASE_PATH="${OUTPUT_BASE_DIR}/codeql_cwe_report_base.json"
else
    echo "Base CodeQL database not found – skipping base analysis."
fi

# Extract the main database to a local directory
export CODEQL_DB_PATH=$(mktemp -d /tmp/cqlcweq-cqldb-XXXXXX)
unzip -q "$CODEQL_ZIP_FOLDER/sss-codeql-database.zip" -d "$CODEQL_DB_PATH"
export CODEQL_DATABASE_PATH="$CODEQL_DB_PATH/.sss-codeql-database"

echo "CodeQL database extracted to: $CODEQL_DATABASE_PATH"

# # Upload main database
# echo "Uploading main CodeQL database..."
# codeql-upload-db --cp_name "$CP_NAME" --project_id "$PROJ_ID" --db_file "$CODEQL_ZIP_FOLDER/sss-codeql-database.zip" --language "$LANG" 2> /dev/null || {
#     echo "Warning: Failed to upload main CodeQL database"
# }

# # Upload buildless database
# echo "Uploading buildless CodeQL database..."
# codeql-upload-db --cp_name "${CP_NAME}-buildless" --project_id "$PROJ_ID" --db_file "$CODEQL_BUILDLESS_ZIP_FOLDER/sss-codeql-database-no-build.zip" --language "$LANG" 2> /dev/null || {
#     echo "Warning: Failed to upload buildless CodeQL database"
# }

echo "=== Function Resolver Setup ==="
export FUNC_IDX_FOLDER="$BACKUP_DIR/generate_full_function_index.target_functions_index"
export FUNC_JSON_FOLDER=$(get_fs generate_full_function_index.target_functions_jsons_dir ${PROJ_ID})

echo "=== Running CWE Analysis ==="
echo "Running CWE queries with backup dir: ${BACKUP_DIR}"
echo "Project: $CP_NAME (ID: $PROJ_ID)"
echo "Output directory: $OUTPUT_BASE_DIR"

# Validate supported language (java/jvm/c/cpp/c++) and start common flow
if [[ "$LANG" == "jvm" || "$LANG" == "java" || "$LANG" == "c" || "$LANG" == "c++" || "$LANG" == "cpp" ]]; then
    echo "Detected project language: $LANG; running CWE queries..."

    # Function resolver selection
    echo ""
    echo "=== Function Resolver Selection ==="
    echo "1. Local function resolver (uses local function index files)"
    echo "2. Remote function resolver (uses remote function resolver service)"
    echo ""
    read -p "Please select function resolver type (1 or 2): " RESOLVER_CHOICE

    case $RESOLVER_CHOICE in
        1)
            echo "Selected: Local function resolver"
            USE_LOCAL_RESOLVER=true

            # Check if function index file exists
            FUNC_INDEX_FILE="$FUNC_IDX_FOLDER/$PROJ_ID"
            if [ ! -f "$FUNC_INDEX_FILE" ]; then
                echo "Error: Function index file not found at $FUNC_INDEX_FILE"
                echo "Available files in $FUNC_IDX_FOLDER:"
                ls -la "$FUNC_IDX_FOLDER" || echo "Directory $FUNC_IDX_FOLDER does not exist"
                exit 1
            fi

            # Check if function JSON directory exists
            if [ ! -d "$FUNC_JSON_FOLDER" ]; then
                echo "Error: Function JSON directory not found at $FUNC_JSON_FOLDER"
                exit 1
            fi

            echo "Using local function index: $FUNC_INDEX_FILE"
            echo "Using local function JSONs: $FUNC_JSON_FOLDER"
            ;;
        2)
            echo "Selected: Remote function resolver"
            USE_LOCAL_RESOLVER=false

            # Check if function index and JSON directories exist for remote setup
            if [ ! -d "$FUNC_IDX_FOLDER" ] || [ ! -d "$FUNC_JSON_FOLDER" ]; then
                echo "Error: Function index or JSON folder not found for remote resolver setup"
                echo "FUNC_IDX_FOLDER: $FUNC_IDX_FOLDER"
                echo "FUNC_JSON_FOLDER: $FUNC_JSON_FOLDER"
                exit 1
            fi

            echo "Setting up remote function resolver..."
            echo "Assuming function resolver service is already running at: $FUNC_RESOLVER_URL"

            # Check if the function resolver service is accessible
            echo "Checking if function resolver service is accessible..."
            if ! curl -s "$FUNC_RESOLVER_URL" > /dev/null 2>&1; then
                echo "Error: Function resolver service is not accessible at $FUNC_RESOLVER_URL"
                echo "Please ensure the function resolver service is running. You can start it with:"
                echo "  cd ../../../services/functionresolver_server"
                echo "  docker-compose up -d"
                exit 1
            fi
            echo "Function resolver service is accessible!"

            # Archive the function index and jsons
            echo "Preparing function data for upload..."
            pushd "$FUNC_IDX_FOLDER" > /dev/null
            rm -f functions_index.tar
            tar -cf functions_index.tar "$PROJ_ID" > /dev/null
            popd > /dev/null

            pushd "$FUNC_JSON_FOLDER" > /dev/null
            rm -f functions_jsons.tar
            tar -cf functions_jsons.tar ./* > /dev/null
            popd > /dev/null

            # Setup temp directory for function resolver
            rm -rf /tmp/func_resolver
            mkdir -p /tmp/func_resolver/functions_index
            mkdir -p /tmp/func_resolver/functions_jsons

            # Copy archives to temp directory
            cp "$FUNC_IDX_FOLDER/functions_index.tar" /tmp/func_resolver/functions_index/
            cp "$FUNC_JSON_FOLDER/functions_jsons.tar" /tmp/func_resolver/functions_jsons/

            # Create combined archive
            pushd /tmp/func_resolver > /dev/null
            tar -cf data.tar ./functions_index/functions_index.tar ./functions_jsons/functions_jsons.tar > /dev/null
            popd > /dev/null

            # Initialize function resolver
            echo "Initializing function resolver with project data..."
            cd "$(dirname "$0")"
            python3 ../init_func_resolver.py || {
                echo "Error: Failed to initialize function resolver"
                echo "Make sure the function resolver service is running and accessible"
                exit 1
            }

            # Cleanup
            rm -rf /tmp/func_resolver

            echo "Remote function resolver initialized successfully!"
            ;;
        *)
            echo "Invalid selection. Please choose 1 or 2."
            exit 1
            ;;
    esac

    # Analysis graph upload selection
    echo ""
    echo "=== Analysis Graph Upload Selection ==="
    echo "Note: For uploading to analysis graph, ensure the analysis graph container (Neo4j) is running"
    echo "1. Upload to analysis graph (default)"
    echo "2. Skip analysis graph upload"
    echo ""
    read -p "Please select analysis graph upload option (1 or 2): " GRAPH_CHOICE

    case $GRAPH_CHOICE in
        1)
            echo "Selected: Upload to analysis graph"
            ANALYSIS_GRAPH_ARGS=""
            ;;
        2)
            echo "Selected: Skip analysis graph upload"
            ANALYSIS_GRAPH_ARGS="--skip-analysis-graph"
            ;;
        *)
            echo "Invalid selection. Please choose 1 or 2."
            exit 1
            ;;
    esac

    # Run the CWE query analysis
    cd "$(dirname "$0")"

    if [ "$USE_LOCAL_RESOLVER" = true ]; then
        echo "Running with local function resolver..."
        python3 run_cwe_queries.py \
            --project-name "$CP_NAME" \
            --project-id "$PROJ_ID" \
            --codeql-cwe-sarif-report "$CODEQL_CWE_SARIF_REPORT_PATH" \
            --codeql-cwe-report "$CODEQL_CWE_REPORT_PATH" \
            --language "$LANG" \
            --full-functions-indices "$FUNC_INDEX_FILE" \
            --functions-json-dir "$FUNC_JSON_FOLDER" \
            --codeql-database-path "$CODEQL_DATABASE_PATH" \
            --local-run \
            --clear-existing-cwe-data \
            $ANALYSIS_GRAPH_ARGS

        if [ "$HAS_BASE_DB" = true ]; then
            echo "Running with base database..."
            python3 run_cwe_queries.py \
                --project-name "$CP_NAME" \
                --project-id "${PROJ_ID}-base" \
                --codeql-cwe-sarif-report "$CODEQL_CWE_SARIF_REPORT_BASE_PATH" \
                --codeql-cwe-report "$CODEQL_CWE_REPORT_BASE_PATH" \
                --language "$LANG" \
                --full-functions-indices "$FUNC_INDEX_FILE" \
                --functions-json-dir "$FUNC_JSON_FOLDER" \
                --codeql-database-path "$CODEQL_BASE_DATABASE_PATH" \
                --local-run \
                --skip-analysis-graph
        fi
    else
        echo "Running with remote function resolver..."
        python3 run_cwe_queries.py \
            --project-name "$CP_NAME" \
            --project-id "$PROJ_ID" \
            --codeql-cwe-sarif-report "$CODEQL_CWE_SARIF_REPORT_PATH" \
            --codeql-cwe-report "$CODEQL_CWE_REPORT_PATH" \
            --language "$LANG" \
            --full-functions-indices "$FUNC_INDEX_FILE" \
            --functions-json-dir "$FUNC_JSON_FOLDER" \
            --codeql-database-path "$CODEQL_DATABASE_PATH" \
            --clear-existing-cwe-data \
            $ANALYSIS_GRAPH_ARGS

        if [ "$HAS_BASE_DB" = true ]; then
            echo "Running with base database..."
            python3 run_cwe_queries.py \
                --project-name "$CP_NAME" \
                --project-id "${PROJ_ID}-base" \
                --codeql-cwe-sarif-report "$CODEQL_CWE_SARIF_REPORT_BASE_PATH" \
                --codeql-cwe-report "$CODEQL_CWE_REPORT_BASE_PATH" \
                --language "$LANG" \
                --full-functions-indices "$FUNC_INDEX_FILE" \
                --functions-json-dir "$FUNC_JSON_FOLDER" \
                --codeql-database-path "$CODEQL_BASE_DATABASE_PATH" \
                --skip-analysis-graph
        fi
    fi

    ANALYSIS_EXIT_CODE=$?

    if [ $ANALYSIS_EXIT_CODE -eq 0 ]; then
        echo "=== Analysis Complete ==="
        echo "Successfully completed CWE analysis for project: $CP_NAME"
        echo "Main SARIF report: $CODEQL_CWE_SARIF_REPORT_PATH"
        echo "Resolved report: $CODEQL_CWE_REPORT_PATH"
        if [ "$ANALYSIS_GRAPH_ARGS" = "--skip-analysis-graph" ]; then
            echo "Analysis graph upload skipped (as requested)"
        else
            echo "Results uploaded to analysis graph"
        fi

        # Display file sizes if reports exist
        if [ -f "$CODEQL_CWE_SARIF_REPORT_PATH" ]; then
            echo "SARIF report size: $(du -h "$CODEQL_CWE_SARIF_REPORT_PATH" | cut -f1)"
        fi
        if [ -f "$CODEQL_CWE_REPORT_PATH" ]; then
            echo "Resolved report size: $(du -h "$CODEQL_CWE_REPORT_PATH" | cut -f1)"
        fi
    else
        echo "=== Analysis Failed ==="
        echo "CWE analysis failed with exit code: $ANALYSIS_EXIT_CODE"
        exit $ANALYSIS_EXIT_CODE
    fi
else
    echo "Warning: Language '$LANG' is not supported. This script supports Java, C, and C++ projects."
    echo "Supported languages: jvm, java, c, c++, cpp"
    exit 1
fi

echo "=== Cleanup ==="
echo "Analysis completed successfully. Results saved to: $OUTPUT_BASE_DIR"
# remove the temp directories if exists
if [ -d "$CODEQL_DB_PATH" ]; then
    rm -rf "$CODEQL_DB_PATH"
fi
if [ -d "$CODEQL_BASE_DB_PATH" ]; then
    rm -rf "$CODEQL_BASE_DB_PATH"
fi
