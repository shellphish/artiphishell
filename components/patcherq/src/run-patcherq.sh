#!/bin/bash

set -x
set -e
set -u

# these exports are together with the `-u` flag to ensure that the inputs are correctly set
export LOCAL_RUN="${LOCAL_RUN}"
export CRS_MODE="${CRS_MODE}"
export PATCHERQ_MODE="${PATCHERQ_MODE}" # {{patcherq_mode | shquote}}
export PATCH_REQUEST_META="${PATCH_REQUEST_META:-}"
export PROJECT_ID="${PROJECT_ID}" # {{project_id | shquote}}
export POI_REPORT_ID="${POI_REPORT_ID:-}" # {{poi_report_id | shquote}}
export CRS_TASK_ANALYSIS_SOURCE="${CRS_TASK_ANALYSIS_SOURCE}" # {{crs_tasks_analysis_source | shquote}}
export CRASHING_INPUT_PATH="${CRASHING_INPUT_PATH:-}" # {{crashing_input_path | shquote}}
# export SANITIZER_STRING="${SANITIZER_STRING}" # {{ vds_record.submission.pou.sanitizer }}"
export PROJECT_NAME="${PROJECT_NAME}" # {{project_name | shquote}}
export POI_REPORT="${POI_REPORT:-}" # {{poi_report | shquote}}
export OSS_FUZZ_REPO="${OSS_FUZZ_REPO}" # {{oss_fuzz_repo | shquote}}
export PROJECT_METADATA="${PROJECT_METADATA}" # {{project_metadata | shquote}}
export FULL_FUNCTIONS_JSONS_DIR="${FULL_FUNCTIONS_JSONS_DIR}" # {{full_functions_jsons_dir | shquote}}
export FULL_FUNCTIONS_INDEX="${FULL_FUNCTIONS_INDEX}" # {{full_functions_index | shquote}}
export FUNCTIONS_BY_FILE_INDEX="${FUNCTIONS_BY_FILE_INDEX}" # {{functions_by_file_index | shquote}}
export DYVA_REPORT="${DYVA_REPORT:-}" # {{ dyva_report | shquote }}

export MAX_ATTEMPTS="${MAX_ATTEMPTS:-10}"
export MAX_POIS="${MAX_POIS:-8}"

export PATCH_OUTPUT_PATH="${PATCH_OUTPUT_PATH}" # {{out_patch | shquote}}
export PATCH_METADATA_OUTPUT_PATH="${PATCH_METADATA_OUTPUT_PATH}" # {{out_patch.cokeyed_dirs.meta | shquote}}

export SARIF_OUTPUT_PATH="${SARIF_OUTPUT_PATH:-}" # {{out_sarif | shquote}}

# This is set ONLY if we are doing a local run
export CODEQL_DB_PATH="${CODEQL_DB_PATH:-}"
export CODEQL_DB_READY="${CODEQL_DB_READY:-}"

export SARIF_INPUT_PATH="${SARIF_INPUT_PATH:-}"
export SARIF_ID="${SARIF_ID:-}"

export DIFF_FILE="${DIFF_FILE:-}"
export CHANGED_FUNCTIONS_INDEX="${CHANGED_FUNCTIONS_INDEX:-}"
export CHANGED_FUNCTIONS_JSONS_DIR="${CHANGED_FUNCTIONS_JSONS_DIR:-}"

export BYPASS_REQUEST_PATH="${BYPASS_REQUEST_PATH:-}"

export PATCHED_ARTIFACTS_DIR="${PATCHED_ARTIFACTS_DIR:-}"
export PATCHED_ARTIFACTS_DIR_LOCK="${PATCHED_ARTIFACTS_DIR_LOCK:-}"


TARGET_SHARED_FOLDER="/shared/patcherq/${PROJECT_ID}/"
mkdir -p "${TARGET_SHARED_FOLDER}"/stats
mkdir -p "$TARGET_SHARED_FOLDER"

#
# Visualization of TEMP_DIR folder:
#    TL;DR: in source-root we have the sources of the challenge
#           in oss-fuzz the original oss-fuzz repo with the oss-fuzz cp info (Dockerfile, project.yaml, etc...
#
#
# /shared/patcherq/
# ├── tmp123456
#   │   ├── source-root (this is the source code of the project)
#   |   │   ├── src
#   │   │   ├── Makefile
#   │   │   ├── ...
#   │   ├── oss-fuzz (this is the oss-fuzz repo)
#   │   │   ├── projects
#   │   │   │   └── nginx
#   │   │   │       ├── Dockerfile
#   │   │   │       ├── project.yaml
#   │   │   │       ├── ...
#   │   |   ├── infra
#   │   |   ├── ...
TEMP_DIR=$(mktemp -d -p $TARGET_SHARED_FOLDER)
rsync -ra "${CRS_TASK_ANALYSIS_SOURCE}/" ${TEMP_DIR}/source-root/
rsync -ra "${OSS_FUZZ_REPO}/" ${TEMP_DIR}/oss-fuzz/

#echo "Temporary directory created: ${TEMP_DIR}"
#echo "Temporary directory created: ${TEMP_DIR_2}"
#exit 1

# ===================
# Little explanation:
# ===================
#  - target_root: this is the path to the project in the oss-fuzz repository (e.g., /src/oss-fuzz/projects/libxml2)
#  - source_root: this is the path to the project's source folder (e.g., the one containing the Makefile and stuff)
#  - poi_report: this is the path to the poi report. This is containing the deduplicated crash report.
#  - function_index: this is a json that, for every function id (key), contains the path of the json to lookup in the target_functions_jsons_dir
#                    to retrieve detailed information regarding a function
#  - target_functions_jsons_dir: this is the path to the directory containing the jsons for each function (as indexed by the function_index)
#  - codeql_db_path: this is the path to the codeql database of the project (important for local runs since we have to update the database ourselves)

if [ "$PATCHERQ_MODE" = "PATCH" ]; then
    python -u /src/run.py \
        --crs_mode "${CRS_MODE}" \
        --patcherq_mode "${PATCHERQ_MODE}" \
        --patch_request_meta "${PATCH_REQUEST_META}" \
        --project_id "${PROJECT_ID}" \
        --target_root "${TEMP_DIR}/oss-fuzz/projects/$PROJECT_NAME" \
        --source_root "${TEMP_DIR}/source-root/" \
        --poi_report "${POI_REPORT}" \
        --poi_report_id "${POI_REPORT_ID}" \
        --project_metadata "${PROJECT_METADATA}" \
        --function_index "${FULL_FUNCTIONS_INDEX}" \
        --crashing_input_path "${CRASHING_INPUT_PATH}" \
        --target_functions_jsons_dir "${FULL_FUNCTIONS_JSONS_DIR}" \
        --functions_by_file_index "${FUNCTIONS_BY_FILE_INDEX}" \
        --dyva_report "${DYVA_REPORT}" \
        --codeql_db_path "${CODEQL_DB_PATH}" \
        --codeql_db_ready "${CODEQL_DB_READY}" \
        --patch_output_path "${PATCH_OUTPUT_PATH}" \
        --sarif_output_path "${SARIF_OUTPUT_PATH}" \
        --patch_metadata_output_path "${PATCH_METADATA_OUTPUT_PATH}" \
        --diff_file "${DIFF_FILE}" \
        --changed_functions_index "${CHANGED_FUNCTIONS_INDEX}" \
        --changed_functions_jsons_dir "${CHANGED_FUNCTIONS_JSONS_DIR}" \
        --bypass_request_output_path "${BYPASS_REQUEST_PATH}" \
        --patched_artifacts_dir "${PATCHED_ARTIFACTS_DIR}" \
        --patched_artifacts_dir_lock "${PATCHED_ARTIFACTS_DIR_LOCK}"

elif [ "$PATCHERQ_MODE" = "REFINE" ]; then
    python -u /src/run.py \
        --crs_mode "${CRS_MODE}" \
        --patcherq_mode "${PATCHERQ_MODE}" \
        --patch_request_meta "${PATCH_REQUEST_META}" \
        --project_id "${PROJECT_ID}" \
        --target_root "${TEMP_DIR}/oss-fuzz/projects/$PROJECT_NAME" \
        --source_root "${TEMP_DIR}/source-root/" \
        --poi_report "${POI_REPORT}" \
        --poi_report_id "${POI_REPORT_ID}" \
        --project_metadata "${PROJECT_METADATA}" \
        --function_index "${FULL_FUNCTIONS_INDEX}" \
        --crashing_input_path "${CRASHING_INPUT_PATH}" \
        --target_functions_jsons_dir "${FULL_FUNCTIONS_JSONS_DIR}" \
        --functions_by_file_index "${FUNCTIONS_BY_FILE_INDEX}" \
        --dyva_report "${DYVA_REPORT}" \
        --codeql_db_path "${CODEQL_DB_PATH}" \
        --codeql_db_ready "${CODEQL_DB_READY}" \
        --patch_output_path "${PATCH_OUTPUT_PATH}" \
        --sarif_output_path "${SARIF_OUTPUT_PATH}" \
        --patch_metadata_output_path "${PATCH_METADATA_OUTPUT_PATH}" \
        --diff_file "${DIFF_FILE}" \
        --changed_functions_index "${CHANGED_FUNCTIONS_INDEX}" \
        --changed_functions_jsons_dir "${CHANGED_FUNCTIONS_JSONS_DIR}" \
        --bypass_request_output_path "${BYPASS_REQUEST_PATH}" \
        --patched_artifacts_dir "${PATCHED_ARTIFACTS_DIR}" \
        --patched_artifacts_dir_lock "${PATCHED_ARTIFACTS_DIR_LOCK}"

elif [ "$PATCHERQ_MODE" = "SARIF" ]; then
    python -u /src/run.py \
        --crs_mode "${CRS_MODE}" \
        --patcherq_mode "${PATCHERQ_MODE}" \
        --project_id "${PROJECT_ID}" \
        --target_root "${TEMP_DIR}/oss-fuzz/projects/$PROJECT_NAME" \
        --source_root "${TEMP_DIR}/source-root/" \
        --project_metadata "${PROJECT_METADATA}" \
        --function_index "${FULL_FUNCTIONS_INDEX}" \
        --target_functions_jsons_dir "${FULL_FUNCTIONS_JSONS_DIR}" \
        --functions_by_file_index "${FUNCTIONS_BY_FILE_INDEX}" \
        --dyva_report "${DYVA_REPORT}" \
        --codeql_db_path "${CODEQL_DB_PATH}" \
        --codeql_db_ready "${CODEQL_DB_READY}" \
        --patch_output_path "${PATCH_OUTPUT_PATH}" \
        --sarif_output_path "${SARIF_OUTPUT_PATH}" \
        --patch_metadata_output_path "${PATCH_METADATA_OUTPUT_PATH}" \
        --sarif_input_path "${SARIF_INPUT_PATH}" \
        --sarif_id "${SARIF_ID}" \
        --diff_file "${DIFF_FILE}" \
        --changed_functions_index "${CHANGED_FUNCTIONS_INDEX}" \
        --changed_functions_jsons_dir "${CHANGED_FUNCTIONS_JSONS_DIR}" \
        --patched_artifacts_dir "${PATCHED_ARTIFACTS_DIR}" \
        --patched_artifacts_dir_lock "${PATCHED_ARTIFACTS_DIR_LOCK}"
else
    echo "Unknown patcherq mode: ${PATCHERQ_MODE}"
    exit 1
fi
