#!/bin/bash

set -ux

export OSS_FUZZ_PROJECT_DIR=${OSS_FUZZ_PROJECT_DIR}
export CRS_TASK_ID=${CRS_TASK_ID}
export PROJECT_SOURCE=${PROJECT_SOURCE:-}
export BUILD_CONFIGURATION_ARCHITECTURE=${BUILD_CONFIGURATION_ARCHITECTURE}
export BUILD_CONFIGURATION_SANITIZER=${BUILD_CONFIGURATION_SANITIZER}
export DYVA_BUILD_ARTIFACT=${DYVA_BUILD_ARTIFACT}
export LOCAL_BUILD=${LOCAL_BUILD:-}

BUILD_IMAGE_COMMAND="oss-fuzz-build-image --instrumentation shellphish_dyva $OSS_FUZZ_PROJECT_DIR"

# if IN_K8S is set, add --push
if [ ! -z "${IN_K8S:-}" ]; then
BUILD_IMAGE_COMMAND="$BUILD_IMAGE_COMMAND --push"
fi

BUILDER_IMAGE=$($BUILD_IMAGE_COMMAND | grep IMAGE_NAME: | awk '{print $2}')
if [ -z "$BUILDER_IMAGE" ]; then echo "BUILDER_IMAGE is empty"; fi
RUNNER_IMAGE=$($BUILD_IMAGE_COMMAND --build-runner-image | grep IMAGE_NAME: | awk '{print $2}')
if [ -z "$RUNNER_IMAGE" ]; then echo "RUNNER_IMAGE is empty"; fi
# the task service for building already handles the pulling of the project_analysis_sources so we don't
# need to do anything with those here
if [ ! -z "$BUILDER_IMAGE" ] && [ ! -z "$RUNNER_IMAGE" ]; then
    if [ -z "${LOCAL_BUILD:-}"]; then
        oss-fuzz-build \
        --use-task-service \
        --project-id ${CRS_TASK_ID} \
        --architecture ${BUILD_CONFIGURATION_ARCHITECTURE} \
        --sanitizer ${BUILD_CONFIGURATION_SANITIZER} \
        --preserve-built-src-dir \
        --instrumentation shellphish_dyva \
        --cpu ${INITIAL_BUILD_CPU:-6} \
        --mem ${INITIAL_BUILD_MEM:-26Gi} \
        --max-cpu ${INITIAL_BUILD_MAX_CPU:-10} \
        --max-mem ${INITIAL_BUILD_MAX_MEM:-40Gi} \
        ${OSS_FUZZ_PROJECT_DIR}
    else
        oss-fuzz-build \
        --project-id ${CRS_TASK_ID} \
        --project-source ${PROJECT_SOURCE} \
        --architecture ${BUILD_CONFIGURATION_ARCHITECTURE} \
        --sanitizer ${BUILD_CONFIGURATION_SANITIZER} \
        --preserve-built-src-dir \
        --instrumentation shellphish_dyva \
        ${OSS_FUZZ_PROJECT_DIR}
    fi
fi

echo "${BUILDER_IMAGE}" >> "${OSS_FUZZ_PROJECT_DIR}/artifacts/builder_image"
echo "${RUNNER_IMAGE}" >> "${OSS_FUZZ_PROJECT_DIR}/artifacts/runner_image"

if [ -d "$OSS_FUZZ_PROJECT_DIR/artifacts" ] && [ "$(ls -A "$OSS_FUZZ_PROJECT_DIR/artifacts/out" 2>/dev/null)" ]; then
    rsync -ra "$OSS_FUZZ_PROJECT_DIR"/artifacts/ ${DYVA_BUILD_ARTIFACT}
else
    mkdir -p "${DYVA_BUILD_ARTIFACT}"
    echo "No artifacts available. Placeholder synced." > "${DYVA_BUILD_ARTIFACT}/placeholder.txt"
fi