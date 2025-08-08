#! /bin/bash

set -x
set -e

export PROJECT_ID="${PROJECT_ID}"
export PROJECT_NAME="${PROJECT_NAME}"
export QUICKSEED_CODEQL_REPORT="${QUICKSEED_CODEQL_REPORT}"

python3 run_codeql_query.py --project-name "${PROJECT_NAME}" --project-id "${PROJECT_ID}" --output-path "${QUICKSEED_CODEQL_REPORT}"