#!/bin/bash

set -x # show commands as they are executed
set -e # fail and exit on any command erroring

TARGET_DIR="$PWD"

TARGET_URL="$1"
TARGET_NAME="$2"
DURATION="${3:-300}"

../common/rebuild_dependency_dockers.sh

# define the variable only if we are local testing
if [ -z "$GITHUB_STEP_SUMMARY" ]; then
    GITHUB_STEP_SUMMARY="/proc/self/fd/1"
    LOCAL_TEST=1
fi

get_target() {
    URL=$1
    LOCALNAME=$2
    if [ ! -d target-$LOCALNAME ]; then
        git clone --recursive $URL target-$LOCALNAME
        pushd target-$LOCALNAME
        if [ ! -z "$ONLY_HARNESSES" ]; then
            COND=$(echo $ONLY_HARNESSES | sed 's/ /" or .key == "/g; s/^/.key == "/; s/$/"/')
            cp ./project.yaml ./project.yaml.orig
            yq eval ".harnesses = (.harnesses | with_entries(select($COND)))" ./project.yaml -i
        fi
        make cpsrc-prepare
        make docker-pull || make docker-build
        popd
    fi
    if [ ! -f target-$LOCALNAME.tar.gz ]; then
        tar -czf target-$LOCALNAME.tar.gz -C target-$LOCALNAME .
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

get_target "$TARGET_URL" "$TARGET_NAME"
echo "works: true" | pd inject aflpp_build_image.project_id 1
pd inject aflpp_build.target 1 < ./target-"$TARGET_NAME".tar.gz

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
