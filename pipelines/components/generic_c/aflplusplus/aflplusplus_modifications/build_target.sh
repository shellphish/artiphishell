#!/bin/bash
set -e
set -x
set -u

export TASK_NAME="${TASK_NAME}"
export TARGET_ID="${TARGET_ID}"
export TARGET_DIR="${TARGET_DIR}"
export DOCKER_ENV_PATH="${DOCKER_ENV_PATH:-}"
export PROJECT_ENV_PATH="${PROJECT_ENV_PATH:-}"
export RESULTS_DIR="${RESULTS_DIR}"
export DOCKER_IMAGE_NAME="${DOCKER_IMAGE_NAME}"

# temp dir in /shared/aflpp/build/ for the build
TEMP_DIR="/shared/${TASK_NAME}/${TARGET_ID}"
mkdir -p "${TEMP_DIR}"
TEMP_DIR=$(mktemp -d -p "${TEMP_DIR}")
rsync -raz --delete "$TARGET_DIR"/ ${TEMP_DIR}/
(
    cd "${TEMP_DIR}"

    if [ -n "${DOCKER_ENV_PATH}" ]; then
        cp "${DOCKER_ENV_PATH}" ./.env.docker
    fi
    if [ -n "${PROJECT_ENV_PATH}" ]; then
        cp "${PROJECT_ENV_PATH}" ./.env.project
    fi

    ./run.sh -x build $@
    rsync -raz ./ "$RESULTS_DIR/"
)
