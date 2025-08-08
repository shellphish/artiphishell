#!/bin/bash

set -x
set -e
set -u
set -o pipefail

# these exports are together with the `-u` flag to ensure that the inputs are correctly set
export CRS_TASK_ANALYSIS_SOURCE="${CRS_TASK_ANALYSIS_SOURCE}" # {{crs_tasks_analysis_source | shquote}}
export CRASHING_INPUT_PATH="${CRASHING_INPUT_PATH}" # {{crashing_input_path | shquote}}
export SANITIZER_STRING="${SANITIZER_STRING}" # {{ vds_record.submission.pou.sanitizer }}"
export PROJECT_NAME="${PROJECT_NAME}" # {{project_name | shquote}}
export POI_REPORT="${POI_REPORT}" # {{poi_report | shquote}}
export OSS_FUZZ_REPO="${OSS_FUZZ_REPO}" # {{oss_fuzz_repo | shquote}}
export PROJECT_METADATA="${PROJECT_METADATA}" # {{project_metadata | shquote}}
export FULL_FUNCTIONS_JSONS_DIR="${FULL_FUNCTIONS_JSONS_DIR:-}" # {{full_functions_jsons_dir | shquote}}
export COMMIT_FUNCTIONS_JSONS_DIR="${COMMIT_FUNCTIONS_JSONS_DIR:-}" # {{commit_functions_jsons_dir | shquote}}
export FULL_FUNCTIONS_INDEX="${FULL_FUNCTIONS_INDEX:-}" # {{full_functions_index | shquote}}
export COMMIT_FUNCTIONS_INDEX="${COMMIT_FUNCTIONS_INDEX:-}" # {{commit_functions_index | shquote}}
export RAW_POVGUY_REPORT="${RAW_POVGUY_REPORT}" # {{povguy_pov_report_path | shquote}}
export KUMUSHI_REPORT="${KUMUSHI_REPORT:-}"
export LOCAL_RUN="${LOCAL_RUN:-}" # {{local_run | shquote}}
export PATCH_REQUESTS_META="${PATCH_REQUESTS_META:-}" # {{patch_requests_meta | shquote}}
export PROJECT_ID="${PROJECT_ID:-all}" # {{project_id | shquote}}

export MAX_ATTEMPTS="${MAX_ATTEMPTS:-10}"
export MAX_POIS="${MAX_POIS:-11}"

export PATCH_OUTPUT_PATH="${PATCH_OUTPUT_PATH}" # {{out_patch | shquote}}
export PATCH_METADATA_OUTPUT_PATH="${PATCH_METADATA_OUTPUT_PATH}" # {{out_patch.cokeyed_dirs.meta | shquote}}
export BYPASSING_INPUTS=${BYPASSING_INPUTS:-} # {{bypasing_inputs | shquote}}

mkdir -p /shared/patchery/${PROJECT_ID:-all}
TEMP_DIR=$(mktemp -d -p /shared/patchery/${PROJECT_ID:-all})
mkdir -p $TEMP_DIR



rsync -ra "${CRS_TASK_ANALYSIS_SOURCE}/" ${TEMP_DIR}/source-root/
rsync -ra "${OSS_FUZZ_REPO}/" ${TEMP_DIR}/oss-fuzz/
cd "${TEMP_DIR}"
ls "${TEMP_DIR}/oss-fuzz/projects/$PROJECT_NAME" || true

PATCHERY_ARGS=(
    --generate-aixcc-patch \
    --target-root "${TEMP_DIR}/oss-fuzz/projects/$PROJECT_NAME" \
    --source-root "${TEMP_DIR}/source-root/" \
    --report-yaml "${POI_REPORT}" \
    --project-metadata "${PROJECT_METADATA}" \
    --function-json-dir "${FULL_FUNCTIONS_JSONS_DIR}" \
    --functions-by-commit-jsons-dir "${COMMIT_FUNCTIONS_JSONS_DIR}" \
    --function-indices "${FULL_FUNCTIONS_INDEX}" \
    --indices-by-commit "${COMMIT_FUNCTIONS_INDEX}" \
    --alerting-inputs "${CRASHING_INPUT_PATH}" \
    --patch-output-dir "${PATCH_OUTPUT_PATH}" \
    --patch-meta-output-dir "${PATCH_METADATA_OUTPUT_PATH}" \
    --raw-report "${RAW_POVGUY_REPORT}" \
    --max-attempts "${MAX_ATTEMPTS}" \
    --max-pois "${MAX_POIS}" \
    --kumushi-report "${KUMUSHI_REPORT}" \
    --patch-requests-meta "${PATCH_REQUESTS_META}" \
    --bypassing-inputs "${BYPASSING_INPUTS}" \
    --patch-planning
)

export USE_LLM_API=1
export LOG_LLM=0

if [ ! -z "${LOCAL_RUN}" ]; then
    DEBUG=1 ipython --pdb $(which patchery) -- "${PATCHERY_ARGS[@]}" --local-run
else
    patchery "${PATCHERY_ARGS[@]}" 
fi

# Safety check before deletion
if [[ -n "$TEMP_DIR" && "$TEMP_DIR" != "/" && "$TEMP_DIR" == /shared/patchery/* ]]; then
    rm -rf "$TEMP_DIR"
else
    echo "Error: TEMP_DIR is not safe to delete: '$TEMP_DIR'"
    exit 1
fi