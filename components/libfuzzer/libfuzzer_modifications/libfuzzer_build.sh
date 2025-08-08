#!/bin/bash
set -e
set -x
set -u

PROJECT_ID="${PROJECT_ID}"
BUILD_NAME="${BUILD_NAME}"
TARGET_DIR="${TARGET_DIR}"
DOCKERFILE_PATH="${DOCKERFILE_PATH}"
DOCKER_ENV_PATH="${DOCKER_ENV_PATH:-}"
PROJECT_ENV_PATH="${PROJECT_ENV_PATH:-}"
RESULTS_DIR="${RESULTS_DIR}"

# temp dir in /shared/libfuzzer/build/ for the build
mkdir -p /shared/libfuzzer/build/
TEMP_DIR=$(mktemp -d -p /shared/libfuzzer/build/)
rsync -raz "$TARGET_DIR"/ ${TEMP_DIR}/
(
    cd "${TEMP_DIR}"

    BASE_IMAGE=$(yq '.docker_image' ./project.yaml)
    CP_NAME=$(yq '.cp_name' ./project.yaml | sed 's/"//g' | sed 's/[^a-zA-Z0-9]/_/g' | tr '[:upper:]' '[:lower:]')
    export DOCKER_IMAGE_NAME="aixcc-libfuzzer-${BUILD_NAME}-${CP_NAME}-${PROJECT_ID}"
    cp /shellphish/libfuzzer/shellphish_libfuzzer*.sh ./
    docker build --build-arg="BASE_IMAGE=${BASE_IMAGE}" -t "${DOCKER_IMAGE_NAME}" -f "$DOCKERFILE_PATH" .

    if [ -n "${DOCKER_ENV_PATH}" ]; then
        cp "${DOCKER_ENV_PATH}" ./.env.docker
    fi
    if [ -n "${PROJECT_ENV_PATH}" ]; then
        cp "${PROJECT_ENV_PATH}" ./.env.project
    fi
    ./run.sh build
    rsync -raz ./ "$RESULTS_DIR/"
)
