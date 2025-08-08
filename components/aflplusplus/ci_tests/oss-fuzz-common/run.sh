#!/bin/bash

set -x # show commands as they are executed
set -eo pipefail # fail and exit on any command erroring

TARGET_DIR="$PWD"

TARGET_PROJECT_DIR="$1"
TARGET_NAME=$(basename "$TARGET_PROJECT_DIR")
HARNESS_NAME="$2"
DURATION="${3:-300}"

../common/rebuild_dependency_dockers.sh

# define the variable only if we are local testing
if [ -z "$GITHUB_STEP_SUMMARY" ]; then
    GITHUB_STEP_SUMMARY="/proc/self/fd/1"
    LOCAL_TEST=1
fi

get_target() {
    TARGET_DIR=$1
    LOCALNAME=$(basename "$TARGET_DIR")
    if [ ! -f target-$LOCALNAME.tar.gz ]; then
        echo "$LOCALNAME" > "$TARGET_DIR/project.name"
        tar -czf target-$LOCALNAME.tar.gz -C "$TARGET_DIR" .
        rm "$TARGET_DIR/project.name"
    fi
}

python scale_down_resources_for_ci.py

for f in ../target-fuzz-common/*.{py,sh}; do
    if [ -f "$(basename $f)" ]; then
        continue
    fi
    cp $f ./
done
pdl --unlock || rm -rf pipeline.lock
ipython --pdb $(which pdl) -- --long-running-timeout $((DURATION / 60))

get_target "$TARGET_PROJECT_DIR"
pd inject aflpp_build.target 1 < ./target-"$TARGET_NAME".tar.gz

printf "harness_name: $HARNESS_NAME\ntarget_id: 1\n" | pd inject aflpp_fuzz.harness_info 1234

set +e
timeout -s INT "${DURATION}" pd --verbose --fail-fast --debug-trace run
set -e

pd status -j | python3 check_results.py "$TARGET_NAME" "$DURATION" 2>&1 | tee -a $GITHUB_STEP_SUMMARY
STATUS=${PIPESTATUS[0]}

if [ "$STATUS" -ne 0 ]; then
    echo "::error title=Pipeline failed::Pipeline failed with status $STATUS"
    exit $STATUS
fi

set +x
