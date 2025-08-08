#!/bin/bash

set -x # show commands as they are executed
set -e # fail and exit on any command erroring

TARGET_DIR="$PWD"

HARNESS_ID="$1"
TARGET_URL="$2"
TARGET_NAME="$3"
DURATION="${4:-960}"

BACKUP_DIR=../../backups/snapchange_build.snapchange_built_target
BACKUP_EXTRACTED_DIR=../../backups/snapchange_build

sudo chmod 666 /dev/kvm

../common/rebuild_dependency_dockers.sh

python scale_down_resources_for_ci.py

pdl --unlock || rm -rf pipeline.lock
ipython --pdb $(which pdl) -- --long-running-timeout $((DURATION / 60))

pd inject snapchange_take_snapshot.snapchange_built_target 1 < $BACKUP_DIR/1.tar.gz

HARNESS_SOURCE_PATH=$(yq ".harnesses.$HARNESS_ID.source" $BACKUP_EXTRACTED_DIR/project.yaml)
HARNESS_BINARY_PATH=$(yq ".harnesses.$HARNESS_ID.binary" $BACKUP_EXTRACTED_DIR/project.yaml)

cat <<EOF | pd inject snapchange_take_snapshot.harness_info 1
project_id: "1"
cp_harness_id: "$HARNESS_ID"
cp_harness_name: "$HARNESS_ID"
cp_harness_source_path: "$HARNESS_SOURCE_PATH"
cp_harness_binary_path: "$HARNESS_BINARY_PATH"
EOF

cat <<EOF | pd inject snapchange_fuzz.syzlang_grammar_input 1
syz_harness(blob buffer[in], blob_size len[blob])
EOF

(cat <<EOF
shellphish:
  known_sources:
    linux_kernel:
    - relative_path: src/linux-kernel
EOF
) >> $BACKUP_EXTRACTED_DIR/project.yaml

cat $BACKUP_EXTRACTED_DIR/project.yaml | pd inject snapchange_build.target_metadata 1

echo "success: true" | pd inject snapchange_build.success 1

set +e
timeout -s INT "${DURATION}" pd --verbose --fail-fast --debug-trace run
set -e

pd status -j | python3 check_results.py "$TARGET_NAME" "$DURATION"

set +x
