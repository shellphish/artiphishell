#!/bin/sh
# This file is meant to be sourced by the pipeline task

RAND=$(head /dev/urandom -c 5 | xxd -p | tr -d '\n')

# new format
cp /jazzer_modifications/Dockerfile.extensions .
BASE_IMAGE=$(yq -r '.docker_image' ./project.yaml)
export DOCKER_IMAGE_NAME="aixcc-jazzer-build-${RAND}"
export DOCKERFILE_PATH="Dockerfile.extensions"

docker build --target base_build --build-arg=BASE_IMAGE=${BASE_IMAGE} -t "${DOCKER_IMAGE_NAME}" -f "$DOCKERFILE_PATH" .

set +x
echo
echo
echo
echo "========= Building Target ========"
set -x

# XXX This should be done in its own task so we don't duplicate the build time
./run.sh build