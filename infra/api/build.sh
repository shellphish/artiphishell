#!/bin/bash

cd $(dirname $0)

set -ex

export AGENT_BUILD_DIR=$(pwd)
export ROOT=$(realpath $(pwd)/../..)

export EXTERNAL_REGISTRY="${EXTERNAL_REGISTRY:-artiphishell.azurecr.io}"

cp $ROOT/.dockerignore $ROOT/.dockerignore.bak
cp .dockerignore $ROOT/.dockerignore

function cleanup() {
    rm $ROOT/.dockerignore -f || true
    mv $ROOT/.dockerignore.bak $ROOT/.dockerignore || true
}

trap cleanup EXIT

export IMAGE_NAME="$EXTERNAL_REGISTRY/aixcc-crs-api:latest"

docker build \
    -t $IMAGE_NAME \
    -f $AGENT_BUILD_DIR/Dockerfile \
    --build-arg IMAGE_PREFIX=$EXTERNAL_REGISTRY/ \
    $ROOT $1
