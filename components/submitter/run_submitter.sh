#!/bin/bash

export SAVED_RESULTS="${SAVED_RESULTS:-/crs_scratch/submission/}"
export CRS_TASK="$CRS_TASK"
export VULN_DIR="$VULN_DIR"
export VULN_METADATA_DIR="$VULN_METADATA_DIR"
export PATCH_DIR="$PATCH_DIR"
export PATCH_METADATA_DIR="$PATCH_METADATA_DIR"
export SARIF_DIR="$SARIF_DIR"
export SARIF_RETRY_DIR="$SARIF_RETRY_DIR"
export CRASH_DIR="$CRASH_DIR"
export SUBMITTED_VULNS="$SUBMITTED_VULNS"
export SUBMITTED_PATCHES="$SUBMITTED_PATCHES"
export SUBMITTED_SARIFS="$SUBMITTED_SARIFS"
export SUBMISSIONS="$SUBMISSIONS"
export SUBMISSION_RESULTS_SUCCESS="$SUBMISSION_RESULTS_SUCCESS"
export SUBMISSION_RESULTS_FAILED="$SUBMISSION_RESULTS_FAILED"
export DEBUG_SUBMITTER=${DEBUG_SUBMITTER:-0}

mkdir -p $SAVED_RESULTS
mkdir -p /tmp/sarif_dir
export $SARIF_DIR=/tmp/sarif_dir

while true; do
  uv run /app/src/submitter.py \
                           --shared-dir $SAVED_RESULTS \
                           --crs-task $CRS_TASK \
                           --vuln-dir $VULN_DIR \
                           --vuln-metadata-dir $VULN_METADATA_DIR \
                           --patch-dir $PATCH_DIR \
                           --patch-metadata-dir $PATCH_METADATA_DIR \
                           --sarif-dir $SARIF_DIR \
                           --sarif-retry-dir $SARIF_RETRY_DIR \
                           --crash-dir $CRASH_DIR \
                           --submitted-vulns $SUBMITTED_VULNS \
                           --submitted-patches $SUBMITTED_PATCHES \
                           --submitted-sarifs $SUBMITTED_SARIFS \
                           --submissions $SUBMISSIONS \
                           --successful-submissions $SUBMISSION_RESULTS_SUCCESS \
                           --failed-submissions $SUBMISSION_RESULTS_FAILED

  if [ $DEBUG_SUBMITTER -eq 1 ]; then
    echo "DEBUG_SUBMITTER is set to 1, exiting early"
    echo "SAVED_RESULTS: $SAVED_RESULTS"
    break
  fi
  sleep 5
done

# This while loop should never exit, so we should never reach this line
exit 1
