#!/bin/bash

set -x
set -e
set -u
set -o pipefail

# these exports are together with the `-u` flag to ensure that the inputs are correctly set

# ensure the pdt env vars are enabled
export TASK_NAME="$TASK_NAME"
export JOB_ID="$JOB_ID"

# ensure the inputs are correctly set
export PROJECT_ID="$PROJECT_ID" # {{ harness_info.project_id | shquote }}
export SNAPCHANGE_BUILT_TARGET="$SNAPCHANGE_BUILT_TARGET" # {{ snapchange_built_target | shquote }}
export CP_HARNESS_ID="$CP_HARNESS_ID" # {{ harness_info.cp_harness_id | shquote }}
export KERNEL_RELPATH="$KERNEL_RELPATH" # {{ target_metadata.shellphish.known_sources.linux_kernel[0].relative_path | shquote }}

# ensure the outputs are correctly set
export SNAPSHOT_SNAPCHANGE_DIR="$SNAPSHOT_SNAPCHANGE_DIR" # {{snapshot_snapchange_dir | shquote}}


# PROCEED TO THE ACTUAL LOGIC

HARNESS_BINARY=$(yq ".harnesses.${CP_HARNESS_ID}.binary" "${SNAPCHANGE_BUILT_TARGET}/project.yaml" | tr -d '"')

export DOCKER_IMAGE_NAME="aixcc-snapchange-${PROJECT_ID}"

TEMP_DIR=/shared/snapchange/take_snapshot/"${PROJECT_ID}_${CP_HARNESS_ID}"
mkdir -p "${TEMP_DIR}"

rsync --delete -ra "${SNAPCHANGE_BUILT_TARGET}/" ${TEMP_DIR}/

cd "${TEMP_DIR}"
FNAME=$(realpath "${HARNESS_BINARY}")
NAME=$(basename "${HARNESS_BINARY}")
DIR_NAME=$(dirname "${FNAME}")
NEW_NAME=$(echo "$NAME" | tr ' ' '_')
if [ "$NEW_NAME" != "$NAME" ]; then
cp "${FNAME}" "$DIR_NAME/$NEW_NAME"
fi

echo "[*] Running make_example.sh"
cd "/snapchange/snapchange/fuzzer" || exit
./make_example.sh "$DIR_NAME/$NEW_NAME" "$SNAPCHANGE_BUILT_TARGET/$KERNEL_RELPATH"

# Test the fuzzer
echo "[*] Testing fuzzer"
./target/release/fuzzer_template project translate

rsync -ra /snapchange/snapchange/ "$SNAPSHOT_SNAPCHANGE_DIR"