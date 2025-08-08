#!/bin/bash

set -x
set -e
set -u
set -o pipefail

# these exports are together with the `-u` flag to ensure that the inputs are correctly set
SNAPSHOT_SNAPCHANGE_DIR="${SNAPSHOT_SNAPCHANGE_DIR}"
SYZLANG_GRAMMAR_INPUT="${SYZLANG_GRAMMAR_INPUT}"
OUTPUTS="${OUTPUTS}"

rsync -ra "${SNAPSHOT_SNAPCHANGE_DIR}"/ /snapchange/snapchange/

cp "${SYZLANG_GRAMMAR_INPUT}" /shellphish/libs/syzlangrs/syzkaller/sys/linux/harness.txt

(
# Kcov filtering
# cp /snapchange_modifications/kcov_filter "${TEMP_DIR}/work/"

/workdir/fuzz.sh \
    -o "$OUTPUTS" \
    -j "$JOB_ID"
# sleep 1d || true
)