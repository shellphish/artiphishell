#!/bin/bash
# set -x
cd ci_tests/oss-fuzz-common/

TARGET_DIR="./targets-afc-oss-fuzz-full-nginx"

if [ ! -d "targets-afc-oss-fuzz-full-nginx" ]; then
  git clone https://github.com/shellphish-support-syndicate/targets-afc-oss-fuzz-full-nginx "$TARGET_DIR"
fi

DURATION="${DURATION:-600}"
./run.sh $TARGET_DIR pov_harness "$DURATION"
