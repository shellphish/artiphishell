#!/bin/bash

set -ex

export PROJECT_ID="$PROJECT_ID"
export PROJECT_NAME="$PROJECT_NAME"
export OSS_FUZZ_REPO_PATH="$OSS_FUZZ_REPO_PATH"
export CANONICAL_BUILD_ARTIFACTS_PATH="$CANONICAL_BUILD_ARTIFACTS_PATH"
export FUNCTION_JSON_PATH="$FUNCTION_JSON_PATH"
export FUNCTION_INDICES_PATH="$FUNCTION_INDICES_PATH"
export PROJECT_METADATA_PATH="$PROJECT_METADATA_PATH"
export CODEQL_REPORT_PATH="$CODEQL_REPORT_PATH"
export CODEQL_CWE_REPORT_PATH="$CODEQL_CWE_REPORT_PATH"
export SEMGREP_REPORT_PATH="$SEMGREP_REPORT_PATH"
export RANKINGS_PATH="$RANKINGS_PATH"
export SCAN_GUY_RESULTS_PATH="$SCAN_GUY_RESULTS_PATH"
TMP_DIR="/shared/code_swipe/$PROJECT_ID"

mkdir -p $TMP_DIR
TARGET_DIR=$(mktemp -d -p $TMP_DIR)

EXTRA_ARGS=""

if [ -n "$DIFFGUY_REPORT_DIR" ]; then
    EXTRA_ARGS="--diffguy-report-dir $DIFFGUY_REPORT_DIR"
fi

if [ -n "$CODEQL_REPORT_PATH" ]; then
    EXTRA_ARGS="$EXTRA_ARGS --codeql-report $CODEQL_REPORT_PATH"
fi
if [ -n "$SEMGREP_REPORT_PATH" ]; then
    EXTRA_ARGS="$EXTRA_ARGS --semgrep-report-path $SEMGREP_REPORT_PATH"
fi
if [ -n "$SEMGREP_REPORT_BASE_PATH" ]; then
    EXTRA_ARGS="$EXTRA_ARGS --semgrep-report-base-path $SEMGREP_REPORT_BASE_PATH"
fi

if [ -n "$CODEQL_CWE_REPORT_PATH" ]; then
     EXTRA_ARGS="$EXTRA_ARGS --codeql-cwe-report $CODEQL_CWE_REPORT_PATH"
fi

if [ -n "$CODEQL_CWE_REPORT_BASE_PATH" ]; then
    EXTRA_ARGS="$EXTRA_ARGS --codeql-cwe-report-base-path $CODEQL_CWE_REPORT_BASE_PATH"
fi

# First we try to find how long it has been since we finished building the canonical build
TIME_DIFF_SECONDS=2400
CURRENT_TIME_EPOCH=$(date +%s)
set +e
if wget -v -O- "$PDT_AGENT_URL/data/canonical_build/done/$PROJECT_ID" --header "Cookie: secret=$PDT_AGENT_SECRET" > /tmp/build_done.yaml; then
    cat /tmp/build_done.yaml
    # end_time: 2025-06-21 20:08:32.589579+00:00
    END_TIME=$(yq -r '.end_time' /tmp/build_done.yaml)
    CURRENT_TIME=$(date -u +"%Y-%m-%d %H:%M:%S")
    END_TIME_EPOCH=$(date -d "$END_TIME" +%s)
    TIME_DIFF_SECONDS=$((CURRENT_TIME_EPOCH - END_TIME_EPOCH))
    echo "Time since canonical build completion: ${TIME_DIFF_SECONDS} seconds"
fi

# Max wait time 40 minutes
MAX_CODE_SWIPE_WAIT_TIME=${MAX_CODE_SWIPE_WAIT_TIME:-2400}
MAX_ENDTIME_EPOCH=$((CURRENT_TIME_EPOCH + MAX_CODE_SWIPE_WAIT_TIME - TIME_DIFF_SECONDS))

# We need to try and manually download scanguy results as they may not exist due to gpu nodes not coming up
SCANGUY_TAR_FILE=$(mktemp -p $TMP_DIR)

for i in $(seq 1 250); do
    if wget -v -O- "$PDT_AGENT_URL/data/scan_guy_$MODE/scan_guy_results/$PROJECT_ID" --header "Cookie: secret=$PDT_AGENT_SECRET" > $SCANGUY_TAR_FILE; then
        export SCAN_GUY_RESULTS_PATH=$(mktemp -d -p $TMP_DIR)
        mkdir -p $SCAN_GUY_RESULTS_PATH
        if tar -xf $SCANGUY_TAR_FILE -C $SCAN_GUY_RESULTS_PATH; then
            break
        else
            rmdir $SCAN_GUY_RESULTS_PATH || true
            unset SCAN_GUY_RESULTS_PATH
        fi
    fi
    
    # Check if we've exceeded the maximum wait time
    if [ $(date +%s) -ge $MAX_ENDTIME_EPOCH ]; then
        echo "Maximum wait time exceeded, giving up on scanguy results"
        break
    fi
    
    echo "Scanguy results not ready yet, waiting 30 seconds... will wait a maximum of $((MAX_ENDTIME_EPOCH - $(date +%s))) seconds more"
    sleep 30
done
set -e


if [ -n "$SCAN_GUY_RESULTS_PATH" ]; then
    EXTRA_ARGS="$EXTRA_ARGS --scanguy-results-path $SCAN_GUY_RESULTS_PATH"
fi
if [ -n "$COMMIT_FUNCTIONS_INDICES" ] && [ -n "$COMMIT_FUNCTIONS_JSONS_DIR" ]; then
    EXTRA_ARGS="$EXTRA_ARGS --commit-functions-index $COMMIT_FUNCTIONS_INDICES --commit-functions-json $COMMIT_FUNCTIONS_JSONS_DIR"
fi

rsync -rav --delete $CANONICAL_BUILD_ARTIFACTS_PATH/ $TARGET_DIR/

python3 /shellphish/code-swipe/src/main.py \
    --project-metadata-path $PROJECT_METADATA_PATH \
    --project-id $PROJECT_ID \
    --project-dir $TARGET_DIR/ \
    --index-dir $FUNCTION_INDICES_PATH \
    --index-dir-json $FUNCTION_JSON_PATH \
    --output-path $RANKINGS_PATH \
    $EXTRA_ARGS
