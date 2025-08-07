#!/bin/bash
set -e
set -x
set -u

export TARGET_DIR="${TARGET_DIR}"
export DOCKERFILE_PATH="${DOCKERFILE_PATH}"
export DOCKER_ENV_PATH="${DOCKER_ENV_PATH:-}"
export PROJECT_ENV_PATH="${PROJECT_ENV_PATH:-}"
export RESULTS_DIR="${RESULTS_DIR}"
export DOCKER_IMAGE_NAME="${DOCKER_IMAGE_NAME}"

/shellphish/coverageguy/build_docker_image.sh

# temp dir in /shared/coverageguy/build/ for the build
mkdir -p /shared/coverageguy/build/
TEMP_DIR=$(mktemp -d -p /shared/coverageguy/build/)
rsync -ra "$TARGET_DIR"/ ${TEMP_DIR}/
(
    cd "${TEMP_DIR}"

    if [ -n "${DOCKER_ENV_PATH}" ]; then
        cp "${DOCKER_ENV_PATH}" ./.env.docker
    fi
    if [ -n "${PROJECT_ENV_PATH}" ]; then
        cp "${PROJECT_ENV_PATH}" ./.env.project
    fi
    ./run.sh build
    rsync -ra "${TEMP_DIR}/" "$RESULTS_DIR/"
)
