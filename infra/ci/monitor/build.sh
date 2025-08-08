#!/bin/bash

SCRIPT_DIR=$(realpath $(dirname $0))

cd $SCRIPT_DIR

set -ex

export AGENT_BUILD_DIR=$(pwd)
export ROOT=$(realpath $(pwd)/../..)

export EXTERNAL_REGISTRY="${EXTERNAL_REGISTRY:-artiphishell.azurecr.io}"

export IMAGE_NAME="$EXTERNAL_REGISTRY/aixcc-crs-monitor:latest"

docker build \
    -t $IMAGE_NAME \
    -f $AGENT_BUILD_DIR/Dockerfile \
    --build-arg IMAGE_PREFIX=$EXTERNAL_REGISTRY/ \
    $SCRIPT_DIR $1


