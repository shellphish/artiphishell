#! /bin/bash

set -x
set -e
set -u
set -o pipefail

TASK_TYPE="${1:-}"
BACKUP_DIR="${2:-}"
PRIMARY_KEY_ID="${3:-}"
OUTPUT_DIR="${4:-}"

if [[ -z "$TASK_TYPE" || -z "$BACKUP_DIR" || -z "$PRIMARY_KEY_ID" || -z "$OUTPUT_DIR" ]]; then
    echo "Usage: $0 <TASK_TYPE> <BACKUP_DIR> <PRIMARY_KEY_ID> <OUTPUT_DIR>"
    echo "All arguments are required."
    exit 1
fi

PRIMARY_KEY_REPO="project_source_path.__footprint.1"

if [ -z "${TASK_TYPE}" ]; then
    echo "Available modes: full, commit"
    read -r TASK_TYPE
fi

if [ "${TASK_TYPE}" == "full" ]; then
    TASK_NAME="antlr4_full_java_parser"
elif [ "${TASK_TYPE}" == "commit" ]; then
    TASK_NAME="antlr4_commit_java_parser"
else
    echo "Invalid mode: ${TASK_TYPE}"
    exit 1
fi

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

    # ensure that the VDS_RECORD_ID exists
    if [ ! -f "${BACKUP_DIR}/${TASK_NAME}.${PRIMARY_KEY_REPO}/${PRIMARY_KEY_ID}.tar.gz" ]; then
        echo "Invalid ${PRIMARY_KEY_REPO}: ${PRIMARY_KEY_ID}"
        exit 1
    fi
fi

if [ ! -f "${BACKUP_DIR}/${TASK_NAME}.${PRIMARY_KEY_REPO}/${PRIMARY_KEY_ID}.tar.gz" ]; then
    echo "Invalid ${PRIMARY_KEY_REPO}: ${PRIMARY_KEY_ID}"
    exit 1
fi

function get_fs() {
    local key="$1"
    local tar_path="$BACKUP_DIR/${key}/${PRIMARY_KEY_ID}.tar.gz"

    if [[ -f "$tar_path" ]]; then
        local extract_dir
        extract_dir=$(mktemp -d)
        tar -xf "$tar_path" -C "$extract_dir"
        echo "$extract_dir"
    else
        echo "ERROR: Tar file not found: $tar_path" >&2
        exit 1
    fi
}

if [ -z "$OUTPUT_DIR" ]; then
    export OUTPUT_DIR=$(mktemp -d)
    echo "Created output dir: $OUTPUT_DIR"
fi
if [ ! -z "${WRITE_TO_BACKUP:-}" ]; then
    OUTPUT_DIR="$BACKUP_DIR/antlr.output_dir/$PRIMARY_KEY_ID"
    mkdir -p "$OUTPUT_DIR"
fi

echo "TASK NAME: $TASK_NAME"
echo "BACKUP DIR: $BACKUP_DIR"
echo "PRIMARY KEY ID: $PRIMARY_KEY_ID"

CRS_TASKS_ANALYSIS_SOURCE_EXTRACTED=$(get_fs "antlr4_full_java_parser.project_source_path.__footprint.1" "$PRIMARY_KEY_ID")
CANONICAL_BUILD_ARTIFACTS_EXTRACTED=$(get_fs "antlr4_full_java_parser.canonical_build_artifact_path" "$PRIMARY_KEY_ID")

echo "CRS_TASKS_ANALYSIS_SOURCE: $CRS_TASKS_ANALYSIS_SOURCE_EXTRACTED"
echo "CANONICAL_BUILD_ARTIFACTS: $CANONICAL_BUILD_ARTIFACTS_EXTRACTED"
echo "OUTPUT_DIR: $OUTPUT_DIR"

python run-java-bottom-up.py --mode $TASK_TYPE --canonical-build-artifact $CANONICAL_BUILD_ARTIFACTS_EXTRACTED --project-source $CRS_TASKS_ANALYSIS_SOURCE_EXTRACTED --output-dir $OUTPUT_DIR
