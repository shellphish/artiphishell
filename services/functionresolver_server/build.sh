#!/bin/bash

cd $(dirname $0)

set -ex

export NAME="aixcc-functionresolver-server"

export BUILD_DIR=$(pwd)
export ROOT=$(realpath $(pwd)/../..)

export EXTERNAL_REGISTRY="${EXTERNAL_REGISTRY:-artiphishell.azurecr.io}"

export IMAGE_NAME="$EXTERNAL_REGISTRY/$NAME:latest"

docker build \
    -t $IMAGE_NAME \
    -f $BUILD_DIR/Dockerfile \
    --build-arg IMAGE_PREFIX=$EXTERNAL_REGISTRY/ \
    $BUILD_DIR


if [ "$1" == "--push" ]; then
    docker push $IMAGE_NAME
fi

