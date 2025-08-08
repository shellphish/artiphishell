#!/bin/bash

source /shellphish/libs/test-utils/backup-handling-utils.sh

INVARIANTS="${INVARIANTS:-}"
BACKUP_DIR="${1:-}"
POI_REPORT_ID="${2:-}"
OUTPUT_DIR="${OUTPUT_DIR:-}"

export LITELLM_KEY='sk-artiphishell'
export AIXCC_LITELLM_HOSTNAME='http://wiseau.seclab.cs.ucsb.edu:666'
export LOCAL_RUN="${LOCAL_RUN:-1}"

PATCHERY_TASK_NAME=patchery
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

if [ -z "${POI_REPORT_ID}" ]; then
    echo "Available POI_REPORT_ID to run: "
    for f in "${BACKUP_DIR}/${PATCHERY_TASK_NAME}.${PRIMARY_KEY_REPO}"/*; do
        echo "$(basename "${f%.yaml}")"
    done
    echo "Which POI_REPORT would you like to run?"
    read -r POI_REPORT_ID

    # ensure that the POI_REPORT_ID exists
    if [ ! -f "${BACKUP_DIR}/${PATCHERY_TASK_NAME}.${PRIMARY_KEY_REPO}/${POI_REPORT_ID}.yaml" ]; then
        echo "Invalid POI_REPORT_ID: ${POI_REPORT_ID}"
        exit 1
    fi
fi

function get_meta() {
    local key=$1
    shift 1
    get_metadata_repo_entry "$BACKUP_DIR/${PATCHERY_TASK_NAME}${key}" $@
}

function lookup_meta_key() {
    get_metadata_key $@
}

function get_fs() {
    local key=$1
    shift 1
    get_filesystem_repo_entry "$BACKUP_DIR/${key}" $@
}

function get_blob() {
    local key=$1
    shift 1
    get_blob_repo_entry "$BACKUP_DIR/${key}" $@.yaml
}
set -x
export POI_REPORT_ID="${POI_REPORT_ID}"
export POI_REPORT_PATH=$(get_meta ".poi_report_meta" "$POI_REPORT_ID")
export PROJECT_ID=$(lookup_meta_key "$POI_REPORT_PATH" ".project_id")
export COVERAGE_BUILD_ARTIFACT=$(get_fs coverage_build.coverage_build_artifacts ${PROJECT_ID})
export TESTGUY_REPORT_PATH=$(get_blob testguy-java.output_testguy_report_path ${PROJECT_ID})

[ -d /shared/testguy_lib ] || mkdir -p /shared/testguy_lib
TEMP_DIR=$(mktemp -d -p /shared/testguy_lib/)
rsync -ra "${COVERAGE_BUILD_ARTIFACT}/" ${TEMP_DIR}

python run.py \
    --project_path "${TEMP_DIR}" \
    --testguy_report_path "${TESTGUY_REPORT_PATH}"
