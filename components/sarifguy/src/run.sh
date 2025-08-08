#!/bin/bash

set -eux

# These are for both dumb and reasonable modes
export LOCAL_RUN="$LOCAL_RUN"
export SARIF_META="$SARIF_META"
export SARIF_PATH="$SARIF_PATH"
export SARIFGUYMODE="$SARIFGUYMODE"
export OUT_FILE_PATH="$OUT_FILE_PATH"
export PROJECT_NAME="$PROJECT_NAME"
export OSS_FUZZ_REPO_PATH="$OSS_FUZZ_REPO_PATH"
export OSS_FUZZ_PROJECT_SRC="$OSS_FUZZ_PROJECT_SRC"
export SARIF_HEARTBEAT_PATH="$SARIF_HEARTBEAT_PATH"

# These are only for the reasonable mode
export FUNCTIONS_INDEX="${FUNCTIONS_INDEX:-None}"
export TARGET_FUNCTIONS_JSONS_DIR="${TARGET_FUNCTIONS_JSONS_DIR:-None}"
export FUNCTIONS_BY_FILE_INDEX="${FUNCTIONS_BY_FILE_INDEX:-None}"

# Create a temporary directory for the debug target
mkdir -p /shared/sarifguy || true

export TMPDIR=$(mktemp -d -p /shared/sarifguy/)
rsync -ra "${OSS_FUZZ_PROJECT_SRC}/" ${TMPDIR}/source-root/
rsync -ra "${OSS_FUZZ_REPO_PATH}/" ${TMPDIR}/oss-fuzz/

# if the SARIFGUYMODE is "reasonable"

if [[ "$SARIFGUYMODE" == "reasonable" ]]; then
    python -u /src/run.py \
        --local-run $LOCAL_RUN \
        --mode $SARIFGUYMODE \
        --sarif-meta $SARIF_META \
        --project-name $PROJECT_NAME \
        --functions-index $FUNCTIONS_INDEX \
        --functions-jsons-dir $TARGET_FUNCTIONS_JSONS_DIR \
        --oss-fuzz-project $TMPDIR/oss-fuzz/projects/$PROJECT_NAME \
        --oss-fuzz-project-src $TMPDIR/source-root \
        --sarif-path $SARIF_PATH \
        --out-path $OUT_FILE_PATH \
        --sarifguy_heartbeat_path $SARIF_HEARTBEAT_PATH
else
    python -u /src/run.py \
        --local-run $LOCAL_RUN \
        --mode $SARIFGUYMODE \
        --sarif-meta $SARIF_META \
        --project-name $PROJECT_NAME \
        --oss-fuzz-project $TMPDIR/oss-fuzz/projects/$PROJECT_NAME \
        --oss-fuzz-project-src $TMPDIR/source-root \
        --sarif-path $SARIF_PATH \
        --out-path $OUT_FILE_PATH \
        --sarifguy_heartbeat_path $SARIF_HEARTBEAT_PATH
fi

