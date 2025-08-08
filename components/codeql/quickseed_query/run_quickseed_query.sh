#! /bin/bash

set -x
set -e

export PROJECT_ID="${PROJECT_ID}"
export PROJECT_NAME="${PROJECT_NAME}"
export QUICKSEED_CODEQL_REPORT="${QUICKSEED_CODEQL_REPORT}"
export CODEQL_VULN_REPORT="${CODEQL_VULN_REPORT}"

python3 /shellphish/codeql/quickseed_query/run_quickseed_query.py --project-name "${PROJECT_NAME}" --project-id "${PROJECT_ID}" --output-path "${QUICKSEED_CODEQL_REPORT}"