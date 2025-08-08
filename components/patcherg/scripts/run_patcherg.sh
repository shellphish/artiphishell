#!/bin/bash
set -e
set -u
set -o pipefail
set -x

export LOCAL_RUN="${LOCAL_RUN:-}" # {{local_run | shquote}}
export PROJECT_NAME="${PROJECT_NAME}" # {{project_name | shquote}}
export PROJECT_ID="${PROJECT_ID}" # {{ project_id | shquote }}
export PATCH_REQUEST_META="${PATCH_REQUEST_META:-}" # {{patch_diff_request | shquote}}
export DISPATCH="${DISPATCH:-}" # {{dispatch | shquote}}
export PATCH_BYPASS_REQUESTS="${PATCH_BYPASS_REQUESTS:-}" # {{patch_bypass_requests | shquote}}
export EMPERORS_CRASH_SUBMISSION_EDICTS="${EMPERORS_CRASH_SUBMISSION_EDICTS:-}" # {{emperors_crash_submission_edicts | shquote}}
export EMPERORS_PATCH_SUBMISSION_EDICTS="${EMPERORS_PATCH_SUBMISSION_EDICTS:-}" # {{emperors_patch_submission_edicts | shquote}}
export CRS_TASK_TYPE="${CRS_TASK_TYPE:-}" # {{crs_task_type | shquote}}

export LOGS="${LOGS:-}" # {{logs | shquote}}
export TEMP_LOGS="${TEMP_LOGS:-}"

mkdir -p /shared/patcherg/
TEMP_DIR=$(mktemp -d -p /shared/patcherg/)


PATCHERG_ARGS=(
    --project-id "$PROJECT_ID" \
    --patch-request-meta "${PATCH_REQUEST_META}" \
    --patch-bypass-requests "${PATCH_BYPASS_REQUESTS}" \
    --crash-submission-edicts "$EMPERORS_CRASH_SUBMISSION_EDICTS" \
    --patch-submission-edicts "$EMPERORS_PATCH_SUBMISSION_EDICTS" \
    --task-type "$CRS_TASK_TYPE"
)

while true; do
  if [ ! -z "${LOCAL_RUN}" ]; then
      ipython --pdb $(which patcherg) -- "${PATCHERG_ARGS[@]}" --local-run
  else
      patcherg "${PATCHERG_ARGS[@]}"
      cp "${TEMP_LOGS}" "${LOGS}/$(tr -dc A-Za-z0-9 </dev/urandom | head -c 16)"
  fi
  sleep 10
done