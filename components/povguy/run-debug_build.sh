#!/bin/bash

set -eu
set -x

export PROJECT_ID="${PROJECT_ID}"
export TARGET_WITH_SOURCES="${TARGET_WITH_SOURCES}"
export DEBUG_BUILT_TARGET_WITH_SOURCES="${DEBUG_BUILT_TARGET_WITH_SOURCES}"

rm -rf /shared/debug_build/${PROJECT_ID}
mkdir -p /shared/debug_build/${PROJECT_ID}
TEMPDIR=$(mktemp -d /shared/debug_build/${PROJECT_ID}/$(date +%s).XXXXXX)

rsync -ra --delete "${TARGET_WITH_SOURCES}"/ $TEMPDIR/
cd $TEMPDIR
oss-fuzz-build \
. \
--sanitizer address \
--instrumentation shellphish_debug

rsync -ra --delete $TEMPDIR/ "$DEBUG_BUILT_TARGET_WITH_SOURCES"/