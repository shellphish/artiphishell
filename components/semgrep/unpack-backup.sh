#!/bin/bash

set -e
set -u
set -x
set -o pipefail

source ../../libs/test-utils/backup-handling-utils.sh

BACKUP_DIR="${1:-}"
PROJECT_ID="${2:-}"

OUTPUT_DIR="${3:-}"

export LITELLM_KEY='sk-artiphishell'
export AIXCC_LITELLM_HOSTNAME='http://wiseau.seclab.cs.ucsb.edu:666'

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

if [ -z "${PROJECT_ID}" ]; then
    echo "Available TARGET_IDs to run: "
    for f in "${BACKUP_DIR}"/oss_fuzz_project_build.project_metadata/*; do
        echo "$(basename "${f%.yaml}")"
    done
    echo "Which PROJECT_ID would you like to run?"
    read -r PROJECT_ID

    # ensure that the PROJECT_ID exists
    if [ ! -f "${BACKUP_DIR}/oss_fuzz_project_build.project_metadata/${PROJECT_ID}.yaml" ]; then
        echo "Invalid PROJECT_ID: ${PROJECT_ID}"
        exit 1
    fi
fi

# if the VDS_RECORD_ID somehow does not exist, then exit
echo "$BACKUP_DIR"
if [ ! -f "${BACKUP_DIR}/oss_fuzz_project_build.project_metadata/${PROJECT_ID}.yaml" ]; then
    echo "Invalid PROJECT_ID: ${PROJECT_ID}"
    exit 1
fi

export METADATA_YAML="${BACKUP_DIR}/oss_fuzz_project_build.project_metadata/${PROJECT_ID}.yaml"
export FUZZ_METADATA_YAML="${BACKUP_DIR}/analyze_target.metadata_path/${PROJECT_ID}.yaml"

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

export PROJECT_NAME="$(lookup_meta_key "$METADATA_YAML" ".shellphish_project_name")"
export instrumentation="$(lookup_meta_key "$METADATA_YAML" '.fuzzing_engines[0]')"

echo "PROJECT_NAME: $PROJECT_NAME"

export PROJECT_ID="$PROJECT_ID"

export CP_IMAGE_READY="$PROJECT_ID"


export TARGET_FUZZ_REPO="$(get_fs "aflpp_build.project_oss_fuzz_repo" "$PROJECT_ID")/projects/$PROJECT_NAME"

export SANITIZER=$(lookup_meta_key "$FUZZ_METADATA_YAML" '.shellphish.sanitizer')
export INSTRUMENTATION=$(lookup_meta_key "$FUZZ_METADATA_YAML" '.shellphish.fuzzing_engine')
export HARNESS=$(lookup_meta_key "$FUZZ_METADATA_YAML" '.shellphish.harnesses[0]')


# build artifacts harness
# seed corpus

echo "TARGET_FUZZ_REPO: $TARGET_FUZZ_REPO"
export JOB_ID="$PROJECT_ID"

read -p "Do you want to rebuild the target? (y/n): " answer

if [[ "$answer" =~ ^[Yy]$ ]]; then
    echo "Rebuidling the target..."
    if [ -z "$OUTPUT_DIR" ]; then
        export OUTPUT_DIR=$(mktemp -d)
        echo "Created output dir: $OUTPUT_DIR"
    fi

    export JAZZER_BUILT_TARGET="${OUTPUT_DIR}/jazzer_built_target" # {{out_patch | shquote}}
    rsync -a "${TARGET_FUZZ_REPO}/" "${JAZZER_BUILT_TARGET}/"

    oss-fuzz-build --sanitizer "$SANITIZER" --instrumentation "$INSTRUMENTATION" "$JAZZER_BUILT_TARGET" --architecture x86_64
    echo "Successfully build target in $JAZZER_BUILT_TARGET"
else
    JAZZER_BUILT_TARGET=""
    if [ -z "${JAZZER_BUILT_TARGET}" ]; then
        echo "Enter build output dir from run-jazzer-build: "
        read -r JAZZER_BUILT_TARGET
        if [ ! -d "${JAZZER_BUILT_TARGET}" ]; then
            echo "Invalid build output dir: $JAZZER_BUILT_TARGET"
            exit 1
        fi
    fi
fi


# # cd jazzer_build.jazzer_build_artifacts
# ls $JAZZER_BUILT_TARGET
# echo "Running fuzzing..."

# oss-fuzz-fuzz "$JAZZER_BUILT_TARGET" "$HARNESS" --sanitizer "$SANITIZER" --instrumentation "$INSTRUMENTATION" --instance-name test --sync-dir /tmp/shared
