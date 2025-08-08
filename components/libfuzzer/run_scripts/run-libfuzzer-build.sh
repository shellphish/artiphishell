#!/bin/bash

set -e
set -u
set -x
export PROJECT_ID=${PROJECT_ID}
export BUILD_ARTIFACTS=${BUILD_ARTIFACTS}
export PROJECT_SOURCE=${PROJECT_SOURCE:-""}
export BUILD_SANITIZER=${BUILD_SANITIZER:-"address"}
export OSS_FUZZ_PROJECT_DIR="${OSS_FUZZ_PROJECT_DIR}"
export TARGET_SPLIT_METADATA="${TARGET_SPLIT_METADATA}"
export BUILD_ARCHITECTURE=${BUILD_ARCHITECTURE:-"x86_64"}

# This code is copied from aijon.
# Ask Wil what it means
BUILD_IMAGE_COMMAND="oss-fuzz-build-image --instrumentation shellphish_libfuzzer $OSS_FUZZ_PROJECT_DIR"
# if IN_K8S is set, add --push
if [ ! -z "${IN_K8S:-}" ]; then
    BUILD_IMAGE_COMMAND="$BUILD_IMAGE_COMMAND --push"
fi

BUILDER_IMAGE=$($BUILD_IMAGE_COMMAND | grep IMAGE_NAME: | awk '{print $2}')
if [ -z "$BUILDER_IMAGE" ]; then exit 1; fi
RUNNER_IMAGE=$($BUILD_IMAGE_COMMAND --build-runner-image | grep IMAGE_NAME: | awk '{print $2}')
if [ -z "$RUNNER_IMAGE" ]; then exit 1; fi
# End ripped off code

if [ ! -z "${IN_PIPELINE:-}" ]; then
    oss-fuzz-build \
        --use-task-service \
        --project-id $PROJECT_ID \
        --sanitizer "${BUILD_SANITIZER}" \
        --architecture "${BUILD_ARCHITECTURE}" \
        --instrumentation "shellphish_libfuzzer" \
        --extra-env "TARGET_SPLIT_METADATA=/out/target_split_metadata" \
        --extra-file "$TARGET_SPLIT_METADATA:/out/target_split_metadata" \
        --cpu ${INITIAL_BUILD_CPU:-6} \
        --mem ${INITIAL_BUILD_MEM:-26Gi} \
        --max-cpu ${INITIAL_BUILD_MAX_CPU:-10} \
        --max-mem ${INITIAL_BUILD_MAX_MEM:-40Gi} \
        "$OSS_FUZZ_PROJECT_DIR"
else
    if [ -z "$PROJECT_SOURCE" ]; then
        echo "Need PROJECT_SOURCE for running locally"
	exit 1
    elif [ ! -d "$PROJECT_SOURCE" ]; then
        echo "PROJECT_SOURCE is not a valid directory: $PROJECT_SOURCE"
	exit 1
    fi
    oss-fuzz-build \
        --project-id $PROJECT_ID \
        --sanitizer "${BUILD_SANITIZER}" \
        --project-source "$PROJECT_SOURCE" \
        --architecture "${BUILD_ARCHITECTURE}" \
        --instrumentation "shellphish_libfuzzer" \
        --extra-env "TARGET_SPLIT_METADATA=/out/target_split_metadata" \
        --extra-file "$TARGET_SPLIT_METADATA:/out/target_split_metadata" \
        "$OSS_FUZZ_PROJECT_DIR"
fi

rsync -ra "$OSS_FUZZ_PROJECT_DIR"/ ${BUILD_ARTIFACTS}/
