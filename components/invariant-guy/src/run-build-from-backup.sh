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

TARGET_FOLDER="${BACKUP_DIR}/invariant_build.target_with_sources.__footprint.1/"

if [ ! -d "${TARGET_FOLDER}" ]; then
    echo "TARGET_FOLDER not found: ${TARGET_FOLDER}"
    exit 1
fi

mkdir -p /shared/invguy/
TMPDIR=$(mktemp -d -p /shared/invguy/)

# Creates the folder where we move the CP!
mkdir -p $TMPDIR/cp-folder
mkdir -p $TMPDIR/cp-folder-built


TARGET_TAR=$(ls "${TARGET_FOLDER}")

echo "TARGET_TAR: ${TARGET_TAR}"

# get the name of the file without the .tar.gz
PROJECT_ID=$(basename "${TARGET_TAR}" .tar.gz)

echo "PROJECT_ID: ${PROJECT_ID}"

if [ -z "${TARGET_TAR}" ]; then
    echo "TARGET_TAR not found: ${TARGET_TAR}"
    exit 1
fi

# extract the TARGET_TAR .tar.gz in the /cp-folder
tar -xf "${TARGET_FOLDER}/${TARGET_TAR}" -C $TMPDIR/cp-folder

TARGET_FOLDER="$TMPDIR/cp-folder"

echo "TARGET: ${TARGET_FOLDER}"

TARGET_METADATA="${BACKUP_DIR}/invariant_build.target_metadata/${PROJECT_ID}.yaml"

echo "TARGET_METADATA: ${TARGET_METADATA}"

# if the cp-folder-built existed, remove it and create it again
if [ -d /cp-folder-built ]; then
    rm -rf /cp-folder-built
fi


CP_FOLDER_BUILT="${TMPDIR}/cp-folder-built"

export TARGET_FOLDER
export TARGET_METADATA
export PROJECT_ID
export CP_FOLDER_BUILT

./run-build.sh

#cd /src

#python /src/invguy-build.py \
#    --target-dir "${TARGET_FOLDER}" \
#    --target-metadata "${TARGET_METADATA}" \
#    --project-id "${PROJECT_ID}" \
#    --target-built "${CP_FOLDER_BUILT}"

#rm -rf $TMPDIR
