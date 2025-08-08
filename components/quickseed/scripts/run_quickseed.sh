#! /bin/bash

set -e
set -x
set -o pipefail
export CRS_TASK_ANALYSIS_SOURCE="${CRS_TASK_ANALYSIS_SOURCE}"
export OSS_FUZZ_REPO="${OSS_FUZZ_REPO}"
export AGGREGATED_HARNESS_INFO="${AGGREGATED_HARNESS_INFO}"
export PROJECT_NAME="${PROJECT_NAME}"
export PROJECT_METADATA="${PROJECT_METADATA}"
export PROJECT_ID="${PROJECT_ID}"
export FULL_FUNCTIONS_JSONS_DIR="${FULL_FUNCTIONS_JSONS_DIR}"
export FULL_FUNCTIONS_INDEX="${FULL_FUNCTIONS_INDEX}"
export COVERAGE_BUILD_ARTIFACTS_PATH="${COVERAGE_BUILD_ARTIFACTS}"
export DEBUG_BUILD_ARTIFACTS_PATH="${DEBUG_BUILD_ARTIFACTS}"
export BUILD_CONFIGURATION_ID="${BUILD_CONFIGURATION_ID}"
export CRASH_DIR_PASS_TO_POV="${CRASH_DIR_PASS_TO_POV}"
export QUICKSEED_CODEQL_REPORT="${QUICKSEED_CODEQL_REPORT:-}"
export QUICKSEED_CODESWIPE_REPORT="${QUICKSEED_CODESWIPE_REPORT:-}"
export CRASH_METADATA_DIR_PASS_TO_POV="${CRASH_METADATA_DIR_PASS_TO_POV}"
export SARIF_REPORT="${SARIF_REPORT:-}"
export SARIF_METADATA_PATH="${SARIF_METADATA_PATH:-}"
export COMMIT_FUNCTIONS_JSONS_DIR="${COMMIT_FUNCTIONS_JSONS_DIR:-}"
export LOCAL_RUN="${LOCAL_RUN:-}"
export QUICKSEED_LOG="${QUICKSEED_LOG:-}"
export QUICKSEED_PATH_BACKUP_REPORT="${QUICKSEED_PATH_BACKUP_REPORT:-}"
export QUICKSEED_CRASHING_SEED_BACKUP="${QUICKSEED_CRASHING_SEED_BACKUP:-}"
export SARIF_RETRY_METADATA="${SARIF_RETRY_METADATA:-}"


mkdir -p /shared/quickseed/

TEMP_DIR=$(mktemp -d -p /shared/quickseed/)
rsync -ra "${CRS_TASK_ANALYSIS_SOURCE}/" ${TEMP_DIR}/source-root/
rsync -ra "${OSS_FUZZ_REPO}/" ${TEMP_DIR}/oss-fuzz/
rsync -ra "${OSS_FUZZ_REPO}/" ${TEMP_DIR}/coverage-build/
rsync -ra "${OSS_FUZZ_REPO}/" ${TEMP_DIR}/oss-fuzz/debug-build/
mkdir -p  ${TEMP_DIR}/coverage-build/
mkdir -p  ${TEMP_DIR}/debug-build/
rsync -ra --delete "${COVERAGE_BUILD_ARTIFACTS_PATH}/"  ${TEMP_DIR}/coverage-build/
rsync -ra --delete "${DEBUG_BUILD_ARTIFACTS_PATH}/"  ${TEMP_DIR}/debug-build/

cd "${TEMP_DIR}"

# TODO: Create this inside quickseed
# export JAZZER_INSTANCE_UNIQUE_NAME=${PROJECT_NAME}-${HARNESS_NAME}-${HARNESS_INFO_ID}/

export TARGET_ROOT="${TEMP_DIR}/oss-fuzz/projects/${PROJECT_NAME}"
export SOURCE_ROOT="${TEMP_DIR}/source-root"
# export FUZZ_DUMP_DIR="/shared/fuzzer_sync/${JAZZER_INSTANCE_UNIQUE_NAME}/sync-quickseed/"
# export CRASH_DIR="${FUZZ_DUMP_DIR}/crashes/"
# export BENIGN_DIR="${FUZZ_DUMP_DIR}/queue/"
export COST_DIR="/shared/quickseed-agentlib-cost"

# mkdir -p "$FUZZ_DUMP_DIR"
# mkdir -p "$CRASH_DIR"
# mkdir -p "$BENIGN_DIR"
mkdir -p "$COST_DIR"

if [ -z "${SARIF_REPORT}" ]; then
    echo "SARIF report not provided. Using default."
  if [ -z "${COMMIT_FUNCTIONS_JSONS_DIR}" ]; then
      echo "Full Mode does not have commit full functions json dir."
      QUICKSEED_ARGS=(
          --project-metadata "${PROJECT_METADATA}" \
          --source-root "${TEMP_DIR}/source-root/" \
          --target-root "${TARGET_ROOT}" \
          --func-dir "${FULL_FUNCTIONS_JSONS_DIR}" \
          --func-index "${FULL_FUNCTIONS_INDEX}" \
          --harness-infos "${AGGREGATED_HARNESS_INFO}" \
          --project-id "${PROJECT_ID}" \
          --coverage-build-target "${TEMP_DIR}/coverage-build/" \
          --debug-build-target "${TEMP_DIR}/debug-build/" \
          --codeql-report "${QUICKSEED_CODEQL_REPORT}" \
          --codeswipe-report "${QUICKSEED_CODESWIPE_REPORT}" 
      )
  else
      echo "Delta Mode"
      QUICKSEED_ARGS=(
          --project-metadata "${PROJECT_METADATA}" \
          --source-root "${TEMP_DIR}/source-root/" \
          --target-root "${TARGET_ROOT}" \
          --func-dir "${FULL_FUNCTIONS_JSONS_DIR}" \
          --func-index "${FULL_FUNCTIONS_INDEX}" \
          --harness-infos "${AGGREGATED_HARNESS_INFO}" \
          --project-id "${PROJECT_ID}" \
          --coverage-build-target "${TEMP_DIR}/coverage-build/" \
          --debug-build-target "${TEMP_DIR}/debug-build/" \
          --codeql-report "${QUICKSEED_CODEQL_REPORT}" \
          --codeswipe-report "${QUICKSEED_CODESWIPE_REPORT}" \
          --commit-full-functions-dir "${COMMIT_FUNCTIONS_JSONS_DIR}"
      )
  fi
else
  echo "SARIF report provided. Using SARIF report."
  QUICKSEED_ARGS=(
      --project-metadata "${PROJECT_METADATA}" \
      --source-root "${TEMP_DIR}/source-root/" \
      --target-root "${TARGET_ROOT}" \
      --func-dir "${FULL_FUNCTIONS_JSONS_DIR}" \
      --func-index "${FULL_FUNCTIONS_INDEX}" \
      --harness-infos "${AGGREGATED_HARNESS_INFO}" \
      --project-id "${PROJECT_ID}" \
      --coverage-build-target "${TEMP_DIR}/coverage-build/" \
      --debug-build-target "${TEMP_DIR}/debug-build/" \
      --sarif-report "${SARIF_REPORT}"
      --sarif-report-metadata "${SARIF_METADATA_PATH}"
  )
fi

# Run QuickSeed
mkdir -p "${QUICKSEED_LOG}"

# Generate log filename with random number
log_file="${QUICKSEED_LOG}/quickseed_${RANDOM}.log"

if [ ! -z "${LOCAL_RUN}" ]; then
  ipython --pdb $(which QuickSeed) -- "${QUICKSEED_ARGS[@]}" --local-run 2>&1 | tee "${log_file}"
  exit_code=$?
else
  QuickSeed "${QUICKSEED_ARGS[@]}" 2>&1 | tee -a "${log_file}"
  exit_code=$?
fi

exit $exit_code
