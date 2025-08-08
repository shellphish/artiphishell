#!/bin/bash

set -x
set -e
set -u
set -o pipefail

# these exports are together with the `-u` flag to ensure that the inputs are correctly set
export CRS_TASK_ANALYSIS_SOURCE="${CRS_TASK_ANALYSIS_SOURCE}" # {{crs_tasks_analysis_source | shquote}}
export CRASHING_INPUT_PATH="${CRASHING_INPUT_PATH:-}" # {{crashing_input_path | shquote}}
export PROJECT_NAME="${PROJECT_NAME}" # {{project_name | shquote}}
export POI_REPORT="${POI_REPORT}" # {{poi_report | shquote}}
export OSS_FUZZ_REPO="${OSS_FUZZ_REPO}" # {{oss_fuzz_repo | shquote}}
export PROJECT_METADATA="${PROJECT_METADATA}" # {{project_metadata | shquote}}
export FULL_FUNCTIONS_JSONS_DIR="${FULL_FUNCTIONS_JSONS_DIR:-}" # {{full_functions_jsons_dir | shquote}}
export COMMIT_FUNCTIONS_JSONS_DIR="${COMMIT_FUNCTIONS_JSONS_DIR:-}" # {{commit_functions_jsons_dir | shquote}}
export FULL_FUNCTIONS_INDEX="${FULL_FUNCTIONS_INDEX:-}" # {{full_functions_index | shquote}}
export COMMIT_FUNCTIONS_INDEX="${COMMIT_FUNCTIONS_INDEX:-}" # {{commit_functions_index | shquote}}
export COVERAGE_BUILD_ARTIFACTS="${COVERAGE_BUILD_ARTIFACTS}" # {{coverage_build_artifacts | shquote}}
export KUMUSHI_OUTPUT="${KUMUSHI_OUTPUT}"
export LOCAL_RUN="${LOCAL_RUN:-}" # {{local_run | shquote}}
export DIFFGUY_REPORTS="${DIFFGUY_REPORTS:-}" # {{diffguy_reports | shquote}}
export CRASHING_INPUT_EXPLORATION_PATH="${CRASHING_INPUT_EXPLORATION_PATH:-}" # {{crashing_input_exploration_path | shquote}}
export DEBUG_BUILD_ARTIFACTS="${DEBUG_BUILD_ARTIFACTS:-}" # {{debug_build_artifacts | shquote}}
export PATCH_REQUEST_META="${PATCH_REQUEST_META:-}" # {{patch_requests_meta | shquote}}
export DYVA_REPORT="${DYVA_REPORT:-}" # {{dyva_report | shquote}}
export USE_LLM_API=1



mkdir -p /shared/kumushi/${PROJECT_ID:-all}
TEMP_DIR=$(mktemp -d -p /shared/kumushi/${PROJECT_ID:-all})
mkdir -p $TEMP_DIR
# Make a unique temp dir for this run so we can easily clean up
TEMP_DIR=$(mktemp -d -p $TEMP_DIR)
mkdir -p $TEMP_DIR

rsync -ra "${CRS_TASK_ANALYSIS_SOURCE}/" ${TEMP_DIR}/source-root/
rsync -ra "${OSS_FUZZ_REPO}/" ${TEMP_DIR}/oss-fuzz/
rsync -ra "${COVERAGE_BUILD_ARTIFACTS}/" ${TEMP_DIR}/coverage_build_artifacts/
rsync -ra "${DEBUG_BUILD_ARTIFACTS}/" ${TEMP_DIR}/debug_build_artifacts/

RCA_MODE="--hybrid-mode"

if [ -z "${DELTA}" ]; then
  COMPETITION_MODE="--full-mode"
else
  COMPETITION_MODE="--delta-mode"
fi

if [ -z "$JAVA" ]; then
  JAVA_MODE=""
else
  JAVA_MODE="--java-mode"

fi

if ! [ -z "${CRASHING_INPUT_EXPLORATION_PATH}" ]; then
  CRASHING_INPUT_EXPLORATION="--crashing-input-dir ${CRASHING_INPUT_EXPLORATION_PATH}"
  echo "Using crashing input dir: ${CRASHING_INPUT_EXPLORATION_PATH}"
else
  CRASHING_INPUT_EXPLORATION=""
  echo "No valid crashing input dir, skipping..."
fi

KUMUSHI_ARGS=(
--source-root "${TEMP_DIR}/source-root/" \
--target-root "${TEMP_DIR}/oss-fuzz/projects/${PROJECT_NAME}" \
--project-metadata "${PROJECT_METADATA}" \
--report-yaml "${POI_REPORT}" \
--function-json-dir "${FULL_FUNCTIONS_JSONS_DIR}" \
--functions-by-commit-jsons-dir "${COMMIT_FUNCTIONS_JSONS_DIR}" \
--function-indices "${FULL_FUNCTIONS_INDEX}" \
--indices-by-commit "${COMMIT_FUNCTIONS_INDEX}" \
--diffguy-reports "${DIFFGUY_REPORTS}" \
--crash-input "${CRASHING_INPUT_PATH}" \
--output-dir "${KUMUSHI_OUTPUT}" \
--coverage-build-project-path "${TEMP_DIR}/coverage_build_artifacts/" \
--debug-build-project-path "${TEMP_DIR}/debug_build_artifacts/" \
--patch-request-meta "${PATCH_REQUEST_META}" \
--dyva-report-path "${DYVA_REPORT}" \
--aixcc \
"${RCA_MODE}" \
"${COMPETITION_MODE}" \
${JAVA_MODE} \
${CRASHING_INPUT_EXPLORATION}
)


if [ ! -z "${LOCAL_RUN}" ]; then
    DEBUG=1 ipython --pdb $(which kumu-shi) -- "${KUMUSHI_ARGS[@]}" --local-run
else
    set +e
    kumu-shi "${KUMUSHI_ARGS[@]}"
    EXIT_CODE=$?
    set -e
     # Check if the process exited with an error code
    if [ $EXIT_CODE -ne 0 ]; then
        echo "=== ERROR DETECTED ==="
        echo "Process exited with code $EXIT_CODE"
        echo "=== RECENT KERNEL MESSAGES (dmesg) ==="
        # Print last 50 lines of dmesg, filtering for recent entries
        dmesg | tail -50
        echo "=== END KERNEL MESSAGES ==="
    fi

    # Clean up the temp dir so we don't run out of space
    rm -rf $TEMP_DIR || true
    exit $EXIT_CODE
fi

