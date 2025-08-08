#!/bin/bash

set -x
set -e
set -u

export LOCAL_RUN="${LOCAL_RUN}"
export PROJECT_ID="${PROJECT_ID}"
export PROJECT_METADATA="${PROJECT_METADATA}"
export COVERAGE_BUILD_ARTIFACT="${COVERAGE_BUILD_ARTIFACT}"
export CRS_TASK_ANALYSIS_SOURCE="${CRS_TASK_ANALYSIS_SOURCE}"
export PROJECT_COMPILE_COMMAND="${PROJECT_COMPILE_COMMAND:-None}"
export OUTPUT_TESTGUY_REPORT_PATH="${OUTPUT_TESTGUY_REPORT_PATH}"

# Coverage Build
# 
# /shared/testguy/
# ├── tmp654321
# │   ├── artifacts
# │   │   └── built_src
# │   │       ├── ...
# │   │   |-- source_root
# │   │       ├── ...
# │   |   |-- work
# │   |       ├── ...
# |   ├── Dockerfile
# |   ├── project.yaml
# |   ├── ...

mkdir -p /shared/testguy/

TEMP_DIR=$(mktemp -d -p /shared/testguy/)
rsync -ra "${COVERAGE_BUILD_ARTIFACT}/" ${TEMP_DIR}
rsync -ra "${CRS_TASK_ANALYSIS_SOURCE}/" "${TEMP_DIR}/artifacts/source_root"

python /shellphish/testguy/src/run.py \
    --project_id "${PROJECT_ID}" \
    --project_path "${TEMP_DIR}" \
    --project_metadata_path "${PROJECT_METADATA}" \
    --compile_cmd_path "${PROJECT_COMPILE_COMMAND}" \
    --output_path "${OUTPUT_TESTGUY_REPORT_PATH}" \
    --local_run "${LOCAL_RUN}" \
