#! /bin/bash

set -e
set -u
set -x

export OSS_FUZZ_PROJECT_DIR="${OSS_FUZZ_PROJECT_DIR}"
export BUILD_SANITIZER=${BUILD_SANITIZER:-"address"}
export HARNESS_NAME="${HARNESS_NAME}"
export INSTANCE_NAME="${INSTANCE_NAME}"

if [ ! -z "${IN_K8S:-}" ]; then
    oss-fuzz-fuzz \
        --use-task-service \
        --build-runner-image \
        --sanitizer "$BUILD_SANITIZER" \
	--instance-name "$INSTANCE_NAME" \
        --instrumentation "shellphish_libfuzzer" \
        "$OSS_FUZZ_PROJECT_DIR" "$HARNESS_NAME"
else
    oss-fuzz-fuzz \
        --build-runner-image \
        --sanitizer "$BUILD_SANITIZER" \
	--instance-name "$INSTANCE_NAME" \
        --instrumentation "shellphish_libfuzzer" \
        "$OSS_FUZZ_PROJECT_DIR" "$HARNESS_NAME"
fi
