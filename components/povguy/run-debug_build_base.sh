#!/bin/bash

set -eu
set -x

export PROJECT_ID="${PROJECT_ID}"
export OSS_FUZZ_PROJECT_DIR="${OSS_FUZZ_PROJECT_DIR}/projects/${PROJECT_NAME}"


rm -rf /shared/debug_build_base/${PROJECT_ID}
mkdir -p /shared/debug_build_base/${PROJECT_ID}
TEMPDIR=$(mktemp -d /shared/debug_build_base/${PROJECT_ID}/$(date +%s).XXXXXX)

rsync -ra --delete "${OSS_FUZZ_PROJECT_DIR}"/ $TEMPDIR/
OSS_FUZZ_PROJECT_DIR=$TEMPDIR

export BUILD_IMAGE_COMMAND="oss-fuzz-build-image --instrumentation libfuzzer $OSS_FUZZ_PROJECT_DIR"
$BUILD_IMAGE_COMMAND | tee $OSS_FUZZ_PROJECT_DIR/.shellphish_build_image.log
$BUILD_IMAGE_COMMAND --build-runner-image | tee $OSS_FUZZ_PROJECT_DIR/.shellphish_build_runner_image.log

BUILDER_IMAGE=$(cat "$OSS_FUZZ_PROJECT_DIR/.shellphish_build_image.log" | grep IMAGE_NAME: | awk '{print $2}')
if [ -z "$BUILDER_IMAGE" ]; then exit 1; fi
RUNNER_IMAGE=$(cat "$OSS_FUZZ_PROJECT_DIR/.shellphish_build_runner_image.log" | grep IMAGE_NAME: | awk '{print $2}')
if [ -z "$RUNNER_IMAGE" ]; then exit 1; fi

oss-fuzz-build \
  --use-task-service \
  --project-id $PROJECT_ID \
  --architecture $ARCHITECTURE \
  --sanitizer $SANITIZER \
  --instrumentation libfuzzer \
  --git-ref "HEAD~1" \
  "$OSS_FUZZ_PROJECT_DIR"

rsync -ra --delete $TEMPDIR/ "$DEBUG_BUILD_BASE_ARTIFACTS"/