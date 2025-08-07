#!/bin/bash
set -e
set -x
set -u

TARGET_DIR="${TARGET_DIR}"
DOCKER_IMAGE_NAME="${DOCKER_IMAGE_NAME}"
DOCKERFILE_PATH="${DOCKERFILE_PATH}"

# temp dir in /shared/aflpp/build/ for the build
(
    cd "${TARGET_DIR}"

    mkdir -p ./shellphish/
    cp -r /shellphish/libfreedom/ ./shellphish/libfreedom/
    cp -r /shellphish/wrap-lib/ ./shellphish/wrap-lib/
    cp -r /shellphish/aflpp/ ./shellphish/aflpp/
    cp -r /afl ./shellphish/afl

    BASE_IMAGE=$(yq -r '.docker_image' ./project.yaml)
    docker build --build-arg=BASE_IMAGE=${BASE_IMAGE} -t "${DOCKER_IMAGE_NAME}" -f "$DOCKERFILE_PATH" .
)
