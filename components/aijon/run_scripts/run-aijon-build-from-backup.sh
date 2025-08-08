#!/bin/bash

set -eu
set -o pipefail

source /shellphish/libs/test-utils/backup-handling-utils.sh

INSTR_ARTIFACT=""
POSITIONAL_ARGS=()

# Parse args
while [[ $# -gt 0 ]]; do
    case "$1" in
        --instr-artifact)
            if [ $# -eq 1 ]; then
                echo "Error: --instr-artifact requires a directory path."
                exit 1
            fi
            shift
            if [[ -z "$1" || "$1" == --* ]]; then
                echo "Error: --instr-artifact requires a directory path."
                exit 1
            fi
            INSTR_ARTIFACT="$1"
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [--instr-artifact <dir>] <backup_dir> <build_config_id>"
            exit 0
            ;;
        --*)
            echo "Unknown option: $1"
            exit 1
            ;;
        *)
            POSITIONAL_ARGS+=("$1")
            shift
            ;;
    esac
done

if [ -n "$INSTR_ARTIFACT" ] && [ ! -d "$INSTR_ARTIFACT" ]; then
    echo "Error: --instr-artifact must be a valid directory."
    exit 1
fi

BACKUP_DIR="${POSITIONAL_ARGS[0]:-}"
BUILD_CONFIGURATION_ID="${POSITIONAL_ARGS[1]:-}"

# BACKUP_DIR="${1:-}"
# BUILD_CONFIGURATION_ID="${2:-}"
OUTPUT_DIR="${OUTPUT_DIR:-}"

TASK_NAME=aijon_build
PRIMARY_KEY_REPO=build_configuration

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

if [ -z "${BUILD_CONFIGURATION_ID}" ]; then
    num_build_configs=$(ls "${BACKUP_DIR}/${TASK_NAME}.${PRIMARY_KEY_REPO}" | wc -l)
    if [ "$num_build_configs" -eq 0 ]; then
        echo "No build configurations found in ${BACKUP_DIR}/${TASK_NAME}.${PRIMARY_KEY_REPO}"
        exit 1
    elif [ "$num_build_configs" -eq 1 ]; then
        yaml_file=$(ls "${BACKUP_DIR}/${TASK_NAME}.${PRIMARY_KEY_REPO}")
        BUILD_CONFIGURATION_ID="${yaml_file%.yaml}"
        echo "Only one build configuration found: ${BUILD_CONFIGURATION_ID}"
    else
        echo "Available BUILD_CONFIGURATIONs to run: "
        for f in "${BACKUP_DIR}/${TASK_NAME}.${PRIMARY_KEY_REPO}"/*; do
            sanitizer=$(yq '.sanitizer' "$f")
            echo "$(basename "${f%.yaml}") - ${sanitizer}"
        done
        echo "Which BUILD_CONFIGURATION would you like to run?"
        read -r BUILD_CONFIGURATION_ID
    fi

    # ensure that the BUILD_CONFIGURATION_ID exists
    if [ ! -f "${BACKUP_DIR}/${TASK_NAME}.${PRIMARY_KEY_REPO}/${BUILD_CONFIGURATION_ID}.yaml" ]; then
        echo "Invalid BUILD_CONFIGURATION_ID: ${BUILD_CONFIGURATION_ID}"
        exit 1
    fi
fi

# if the CRASHING_INPUT_ID somehow does not exist, then exit
echo "$BACKUP_DIR"
if [ ! -f "${BACKUP_DIR}/${TASK_NAME}.${PRIMARY_KEY_REPO}/${BUILD_CONFIGURATION_ID}.yaml" ]; then
    echo "Invalid BUILD_CONFIGURATION_ID: ${BUILD_CONFIGURATION_ID}"
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

if [ -z "$OUTPUT_DIR" ]; then
    export OUTPUT_DIR=$(mktemp -d)
    echo "Created output dir: $OUTPUT_DIR"
fi

export BUILD_CONFIGURATION_ID="$BUILD_CONFIGURATION_ID"
export BUILD_CONFIGURATION=$(get_blob "aijon_build.build_configuration" "${BUILD_CONFIGURATION_ID}.yaml")
export BUILD_CONFIGURATION_ARCHITECTURE=$(lookup_meta_key "$BUILD_CONFIGURATION" ".architecture")
export BUILD_CONFIGURATION_SANITIZER=$(lookup_meta_key "$BUILD_CONFIGURATION" ".sanitizer")
export CRS_TASK_ID=$(lookup_meta_key "$BUILD_CONFIGURATION" ".project_id")
export PROJECT_ID=${CRS_TASK_ID}
export CRS_PROJECT_NAME=$(lookup_meta_key "$BUILD_CONFIGURATION" ".project_name")
export OSS_FUZZ_PROJECT=$(get_fs "pipeline_input.oss_fuzz_repo" "$CRS_TASK_ID")
export OSS_FUZZ_PROJECT_DIR="${OSS_FUZZ_PROJECT}/projects/${CRS_PROJECT_NAME}"
export CRS_TASK_ANALYSIS_SOURCE=$(get_fs "aijon_build.project_analysis_source" "$PROJECT_ID")
if [ -n "$INSTR_ARTIFACT" ]; then
    export INSTRUMENTATION_ARTIFACTS="$INSTR_ARTIFACT"
else
    export INSTRUMENTATION_ARTIFACTS=$(get_fs "aijon_build.aijon_instrumentation_artifact" "$PROJECT_ID")
fi
export BUILD_PATCH_FILE="$INSTRUMENTATION_ARTIFACTS/aijon_instrumentation.patch"
export AFL_ALLOW_LIST="$INSTRUMENTATION_ARTIFACTS/aijon_allowlist.txt"
export BUILD_ARTIFACTS=${OUTPUT_DIR}
export BUILD_ARCHITECTURE=${BUILD_CONFIGURATION_ARCHITECTURE}
export BUILD_SANITIZER=${BUILD_CONFIGURATION_SANITIZER}

PROJECT_METADATA=$(get_blob "dyva_agent.project_metadata" "$PROJECT_ID.yaml")
export LANGUAGE=$(lookup_meta_key "$PROJECT_METADATA" ".language")

/aijon/run_scripts/run-aijon-build.sh
echo "Created output dir: $OUTPUT_DIR"