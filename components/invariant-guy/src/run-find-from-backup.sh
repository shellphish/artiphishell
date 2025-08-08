#!/bin/bash

#set -eux
BACKUP_DIR="${1}"

# Check if there are two arguments
if [ "$#" -ne 1 ]; then
    echo "Illegal number of parameters"
    echo "Usage: $0 BACKUP_DIR"
    exit 1
fi

# if BACKUP_DIR is a .tar.gz we need to extract it (in the destination folder)
if [[ "${BACKUP_DIR}" == *.tar.gz ]]; then
    DESTINATION_FOLDER=$(dirname "${BACKUP_DIR}")
    # Do we have already the folder, if not we extract it
    if [ ! -d "${DESTINATION_FOLDER}/$(basename "${BACKUP_DIR}" .tar.gz)" ]; then
        echo "Extracting backup..."
        tar -xzf "${BACKUP_DIR}" -C "${DESTINATION_FOLDER}"
        BACKUP_DIR="${DESTINATION_FOLDER}/$(basename "${BACKUP_DIR}" .tar.gz)"
    else
        echo "Backup already extracted."
        BACKUP_DIR="${DESTINATION_FOLDER}/$(basename "${BACKUP_DIR}" .tar.gz)"
    fi
fi

echo "BACKUP_DIR: ${BACKUP_DIR}"


# display all the files in the "${BACKUP_DIR}/invariant_find_c.vds_record/ and ask the user which one to use
echo "VDS_RECORDS:"
ls "${BACKUP_DIR}/invariant_find_c.vds_record/"

read -e -p "Enter vds record name: " VDS_RECORD_ID

# get the VDS record first
VDS_RECORD="${BACKUP_DIR}/invariant_find_c.vds_record/${VDS_RECORD_ID}"
if [ ! -f "${VDS_RECORD}" ]; then
    echo "VDS_RECORD not found: ${VDS_RECORD}"
    exit 1
fi


mkdir -p /shared/invguy/
TMPDIR=$(mktemp -d -p /shared/invguy/)

CP_FOLDER_BUILT="${TMPDIR}/cp-folder-built"
SEEDS_DIR="${TMPDIR}/benign_seeds"

# Clean 🧹
rm -rf ${CP_FOLDER_BUILT}
rm -rf ${SEEDS_DIR}

# Create 🪄
mkdir -p ${CP_FOLDER_BUILT}
mkdir -p ${SEEDS_DIR}


CRASHING_COMMIT_ID=$(yq -r '.crashing_commit_id' "${VDS_RECORD}")
CRASHING_COMMIT_REPORT="${BACKUP_DIR}/invariant_find_c.crashing_commit/${CRASHING_COMMIT_ID}.yaml"
if [ ! -f "${CRASHING_COMMIT_REPORT}" ]; then
    echo "CRASHING_COMMIT_REPORT not found: ${CRASHING_COMMIT_REPORT}"
    exit 1
fi
CRASHING_COMMIT=$(yq -r '.crashing_commit' "${CRASHING_COMMIT_REPORT}")

echo "CRASHING_COMMIT: ${CRASHING_COMMIT}"

POI_REPORT_ID=$(yq -r '.crash_report_id' "${CRASHING_COMMIT_REPORT}")
POI_REPORT="${BACKUP_DIR}/invariant_find_c.poi_report/${POI_REPORT_ID}.yaml"

if [ ! -f "${POI_REPORT}" ]; then
    echo "POI_REPORT not found: ${POI_REPORT}"
    exit 1
fi

echo "POI_REPORT: ${POI_REPORT}"

PROJECT_ID=$(yq -r '.project_id' "${POI_REPORT}")

echo "PROJECT_ID: ${PROJECT_ID}"

TARGET_BUILT_WITH_INSTRUMENTATION="${BACKUP_DIR}/invariant_build.target_built_with_instrumentation/${PROJECT_ID}.tar.gz"
if [ ! -f "${TARGET_BUILT_WITH_INSTRUMENTATION}" ]; then
    echo "TARGET_BUILT_WITH_INSTRUMENTATION not found: ${TARGET_BUILT_WITH_INSTRUMENTATION}"
    exit 1
fi


# extract the TARGET_BUILT_WITH_INSTRUMENTATION .tar.gz
tar -xf "${TARGET_BUILT_WITH_INSTRUMENTATION}" -C ${CP_FOLDER_BUILT}

TARGET_BUILT_WITH_INSTRUMENTATION=${CP_FOLDER_BUILT}

FUNCTION_BY_FILE_INDEX_REPORT="${BACKUP_DIR}/invariant_find_c.functions_by_file_index/${PROJECT_ID}"
if [ ! -f "${FUNCTION_BY_FILE_INDEX_REPORT}" ]; then
    echo "FUNCTION_BY_FILE_INDEX_REPORT not found: ${FUNCTION_BY_FILE_INDEX_REPORT}${PROJECT_ID}"
    exit 1
fi

echo "FUNCTION_BY_FILE_INDEX_REPORT: ${FUNCTION_BY_FILE_INDEX_REPORT}"

REPRESENTATIVE_CRASHING_HARNESS_INPUT="${BACKUP_DIR}/invariant_find_c.representative_crashing_harness_input/${POI_REPORT_ID}"
if [ ! -f "${REPRESENTATIVE_CRASHING_HARNESS_INPUT}" ]; then
    echo "REPRESENTATIVE_CRASHING_HARNESS_INPUT not found: ${REPRESENTATIVE_CRASHING_HARNESS_INPUT}"
    exit 1
fi

echo "REPRESENTATIVE_CRASHING_HARNESS_INPUT: ${REPRESENTATIVE_CRASHING_HARNESS_INPUT}"

SIMILAR_HARNESS_INPUT_DIR="${BACKUP_DIR}/invariant_find_c.similar_harness_inputs_dir/"

# Search in the similar harness input dir if we have a .tar.gz named with the VDS_RECORD_ID
# if yes, the name of the tar is assigned to SIMILAR_HARNESS_INPUT_FILE
VDS_RECORD_ID_NO_EXTENSION=$(echo "${VDS_RECORD_ID}" | cut -d'.' -f1)
SIMILAR_HARNESS_INPUT_FILE=$(ls "${SIMILAR_HARNESS_INPUT_DIR}" | grep "${VDS_RECORD_ID_NO_EXTENSION}")

if [ -z "${SIMILAR_HARNESS_INPUT_FILE}" ]; then
    echo "SIMILAR_HARNESS_INPUT_FILE not found: ${SIMILAR_HARNESS_INPUT_FILE}"
    exit 1
fi

#echo "SIMILAR_HARNESS_INPUT_FILE: ${SIMILAR_HARNESS_INPUT_FILE}"

echo tar -xf "${SIMILAR_HARNESS_INPUT_DIR}/${SIMILAR_HARNESS_INPUT_FILE}" -C "${SEEDS_DIR}"

tar -xf "${SIMILAR_HARNESS_INPUT_DIR}/${SIMILAR_HARNESS_INPUT_FILE}" -C "${SEEDS_DIR}"

# update the SIMILAR_HARNESS_INPUT_DIR to the folder created
SIMILAR_HARNESS_INPUT_DIR="${SEEDS_DIR}"

echo "SIMILAR_HARNESS_INPUT_DIR: ${SIMILAR_HARNESS_INPUT_DIR}"

TARGET_METADATA="${BACKUP_DIR}/invariant_build.target_metadata/${PROJECT_ID}.yaml"
if [ ! -f "${TARGET_METADATA}" ]; then
    echo "TARGET_METADATA not found: ${TARGET_METADATA}.yaml"
    exit 1
fi

echo "TARGET_METADATA: ${TARGET_METADATA}" 

# if the folder /DBG-OUT does not exist, create it
# else, wipe it and create it 
if [ -d /dbg-out ]; then
    rm -rf /dbg-out
fi

if [ ! -d /dbg-out ]; then
    mkdir -p /dbg-out
fi

OUT_REPORT_AT="/dbg-out/invariant-report.yaml"

export TARGET_BUILT_WITH_INSTRUMENTATION
export TARGET_METADATA
export SIMILAR_HARNESS_INPUT_DIR
export REPRESENTATIVE_CRASHING_HARNESS_INPUT
export CRASHING_COMMIT
export POI_REPORT
export FUNCTION_BY_FILE_INDEX_REPORT
export OUT_REPORT_AT

./run-find.sh
