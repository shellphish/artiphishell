#!/bin/bash

set -e
set -x

TARGETS=(
    "1 c apache-httpd"
    "2 c oss-fuzz_ideal_apache-httpd"
    "3 c oss-fuzz_minimal_apache-httpd"
)
for TARGET in "${TARGETS[@]}"; do
    TARGET_ID=$(echo "$TARGET" | awk '{print $1}')
    TARGET_LANG=$(echo "$TARGET" | awk '{print $2}')
    TARGET_NAME=$(echo "$TARGET" | awk '{print $3}')
    TARGET_PATH=../components/pipeline/targets_semis/"$TARGET_LANG"/"$TARGET_NAME"
    pushd "$TARGET_PATH"
    ./package.sh
    popd
    pd inject buildguyAFL.target "$TARGET_ID" < "$TARGET_PATH.tar.gz"
done
