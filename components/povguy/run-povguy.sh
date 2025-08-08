#!/bin/bash
set -exu

export PROJECT_ID="$PROJECT_ID"
export PROJECT_NAME="$PROJECT_NAME"
export CRASHING_INPUT_ID="$CRASHING_INPUT_ID"
export DEBUG_BUILD_ARTIFACTS_PATH="$DEBUG_BUILD_ARTIFACTS_PATH"
export CRASHING_INPUT_METADATA_PATH="$CRASHING_INPUT_METADATA_PATH"
export CP_HARNESS_NAME="$CP_HARNESS_NAME"
export CRASHING_INPUT_PATH="$CRASHING_INPUT_PATH"
export CRASH_ID="$CRASH_ID"

export PER_CRASH_FULL_POV_REPORT_PATH="$PER_CRASH_FULL_POV_REPORT_PATH"

export DEDUP_POV_REPORT_PATH="$DEDUP_POV_REPORT_PATH"
export DEDUP_POV_REPORT_REPRESENTATIVE_CRASH="$DEDUP_POV_REPORT_REPRESENTATIVE_CRASH"
export DEDUP_POV_REPORT_REPRESENTATIVE_METADATA="$DEDUP_POV_REPORT_REPRESENTATIVE_METADATA"
export DEDUP_POV_REPORT_REPRESENTATIVE_FULL_REPORT="$DEDUP_POV_REPORT_REPRESENTATIVE_FULL_REPORT"

export LOSAN_POV_REPORT_PATH="$LOSAN_POV_REPORT_PATH"
export LOSAN_REPRESENTATIVE_CRASH="$LOSAN_REPRESENTATIVE_CRASH"
export LOSAN_REPRESENTATIVE_METADATA="$LOSAN_REPRESENTATIVE_METADATA"
export LOSAN_REPRESENTATIVE_FULL_REPORT="$LOSAN_REPRESENTATIVE_FULL_REPORT"

tmpdir=/shared/debug_build/$TASK_NAME/$PROJECT_ID/$CRASHING_INPUT_ID

export TARGET_TMP_DIR=$tmpdir

mkdir -p $tmpdir

TARGET_DIR=$(mktemp -d -p $tmpdir)

rsync -ra --delete $DEBUG_BUILD_ARTIFACTS_PATH/ $TARGET_DIR/

set +e
python /shellphish/povguy/povguy.py \
    --base-meta-path $CRASHING_INPUT_METADATA_PATH \
    --project-dir $TARGET_DIR \
    --harness-name $CP_HARNESS_NAME \
    --pov-path $CRASHING_INPUT_PATH \
    --crash-id $CRASH_ID \
    --out-per-crash-full-pov-report-path $PER_CRASH_FULL_POV_REPORT_PATH \
    --out-dedup-pov-report-path $DEDUP_POV_REPORT_PATH \
    --out-dedup-pov-report-representative-crash $DEDUP_POV_REPORT_REPRESENTATIVE_CRASH \
    --out-dedup-pov-report-representative-metadata $DEDUP_POV_REPORT_REPRESENTATIVE_METADATA \
    --out-dedup-pov-report-representative-full-report $DEDUP_POV_REPORT_REPRESENTATIVE_FULL_REPORT \
    --out-dedup-losan-report-path $LOSAN_POV_REPORT_PATH \
    --out-dedup-losan-report-representative-crash $LOSAN_REPRESENTATIVE_CRASH \
    --out-dedup-losan-report-representative-metadata $LOSAN_REPRESENTATIVE_METADATA \
    --out-dedup-losan-report-representative-full-report $LOSAN_REPRESENTATIVE_FULL_REPORT
EXIT_CODE=$?
set -e

# clean up the build artifacts to avoid clogging up the disk space
# here, we wipe the TARGET_TMP_DIR to ensure the temporary base artifact is wiped as well
rm -rf "$TARGET_TMP_DIR"
exit $EXIT_CODE