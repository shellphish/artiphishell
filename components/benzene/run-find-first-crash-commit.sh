#!/bin/bash
set -x
set -e

export CP_REPO="$CP_REPO"
export CRASH_INPUT_PATH="$CRASH_INPUT_PATH"
export CRASH_INPUT_META="$CRASH_INPUT_META"
export CRASH_INPUT_ID="$CRASH_INPUT_ID"
export OUTPUT="$OUTPUT"
export OUTPUT_DEDUP="$OUTPUT_DEDUP"

mkdir -p /shared/find_commit
WORKING_DIR=$(mktemp -d -p /shared/find_commit)

rsync -ra "$CP_REPO" "/$WORKING_DIR/"
cd $WORKING_DIR

echo $CRASH_INPUT_PATH $CRASH_INPUT_META $CRASH_INPUT_ID $OUTPUT $OUTPUT_DEDUP
export PYTHONUNBUFFERED=1
python3 /find-first-crash-commit/find_first_crash_commit.py --cp-repo $CP_REPO \
                                                            --working-dir $WORKING_DIR \
                                                            --crash-input-path $CRASH_INPUT_PATH \
                                                            --crash-input-meta $CRASH_INPUT_META \
                                                            --crash-input-id $CRASH_INPUT_ID \
                                                            --output $OUTPUT \
                                                            --output-dedup $OUTPUT_DEDUP
sleep 10