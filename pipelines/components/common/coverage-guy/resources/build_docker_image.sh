#!/bin/bash
set -e
set -x
set -u

TARGET_DIR="${TARGET_DIR}"
DOCKER_IMAGE_NAME="${DOCKER_IMAGE_NAME}"
DOCKERFILE_PATH="${DOCKERFILE_PATH}"

# temp dir in /shared/coverageguy/build/ for the build
(
    cd "${TARGET_DIR}"

    # The resources folder is copied into /shellphish/coverageguy
    # so we can grab resources from there
    mkdir -p ./shellphish/
    cp -r /shellphish/wrap-lib/ ./shellphish/wrap-lib
    cp -r /shellphish/coverageguy/ ./shellphish/coverageguy

    BASE_IMAGE=$(yq -r '.docker_image' ./project.yaml)
    docker build --build-arg=BASE_IMAGE=${BASE_IMAGE} -t "${DOCKER_IMAGE_NAME}" -f "$DOCKERFILE_PATH" .
)
