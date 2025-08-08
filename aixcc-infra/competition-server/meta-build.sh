#!/bin/bash
set -ex

SCRIPT_DIR=$(dirname $(realpath $0))

export EXTERNAL_REGISTRY="${EXTERNAL_REGISTRY:-artiphishell.azurecr.io}"
export GITHUB_TOKEN="${GITHUB_TOKEN:-}"

pushd $SCRIPT_DIR
    NAME="aixcc-competition-server-infra"
    IMAGE_NAME="$EXTERNAL_REGISTRY/$NAME:latest"
    docker build -t ${IMAGE_NAME} . --build-arg IMAGE_PREFIX=$EXTERNAL_REGISTRY/ --build-arg GITHUB_TOKEN=$GITHUB_TOKEN $1
popd
