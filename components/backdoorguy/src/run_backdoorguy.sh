#!/bin/bash

set -x
set -e
set -u

# ====== REQUIRED ARGUMENTS ======
export PROJECT_ID="${PROJECT_ID}"
export PROJECT_NAME="${PROJECT_NAME}"
export PROJECT_METADATA_PATH="${PROJECT_METADATA_PATH}"

export OSS_FUZZ_REPO_PATH="${OSS_FUZZ_REPO_PATH}"
export CRS_TASK_ANALYSIS_SOURCE="${CRS_TASK_ANALYSIS_SOURCE}"

export FUNCTIONS_INDEX="${FUNCTIONS_INDEX}"
export FUNCTIONS_JSONS_DIR="${TARGET_FUNCTIONS_JSONS_DIR}"

export OUT_PATH="${OUT_PATH}"
export LOCAL_RUN="${LOCAL_RUN}"

# ====== DIRECTORIES ======
TARGET_SHARED_FOLDER="/shared/backdoorguy/${PROJECT_ID}/"
mkdir -p $TARGET_SHARED_FOLDER || true

echo "Listing OSS_FUZZ_REPO_PATH: $OSS_FUZZ_REPO_PATH"
ls $OSS_FUZZ_REPO_PATH

TEMP_DIR=$(mktemp -d -p $TARGET_SHARED_FOLDER)
rsync -ra "${OSS_FUZZ_REPO_PATH}/" ${TEMP_DIR}/oss-fuzz/
rsync -ra "${CRS_TASK_ANALYSIS_SOURCE}/" ${TEMP_DIR}/source-root/

# ====== RUN BACKDOORGUY ======
echo "*****************************************"
echo "STARTING BACKDOOR GUY!"
echo "*****************************************"

python /src/run.py \
    --project_id "${PROJECT_ID}" \
    --project_metadata "${PROJECT_METADATA_PATH}" \
    --oss_fuzz_project "${TEMP_DIR}/oss-fuzz/projects/${PROJECT_NAME}" \
    --oss_fuzz_project_src "${TEMP_DIR}/source-root" \
    --functions_index "${FUNCTIONS_INDEX}" \
    --functions_jsons_dir "${FUNCTIONS_JSONS_DIR}" \
    --out_path "${OUT_PATH}" \
    --local_run "${LOCAL_RUN}"

echo "*****************************************"
echo "BACKDOOR GUY FINISHED!"
echo "*****************************************"
