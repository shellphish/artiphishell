#!/bin/bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
set -ex
(
    cd "${SCRIPT_DIR}/../../../../"
    ./local_run/rebuild_local.sh build-all image-aixcc-aflplusplus
)

function docker_build_cached() {
    IMAGE_NAME=$1
    FOLDER=$2

    CACHE_DIR="/tmp/cache/docker-cache/${IMAGE_NAME}"
    mkdir -p $CACHE_DIR
    pushd "${SCRIPT_DIR}/../../"
    if [ ! -z "$ACT" ] || [ -z "$GITHUB_ACTIONS" ] || [ "$RUNNER_ENVIRONMENT" = "self-hosted" ]; then
        docker build -t "$IMAGE_NAME" "$FOLDER"
    else
        docker buildx build \
            --tag "$IMAGE_NAME" \
            --build-arg IMAGE_PREFIX=ghcr.io/shellphish-support-syndicate/ \
            --cache-from type=local,src=$CACHE_DIR \
            --cache-to type=local,dest=$CACHE_DIR-new,mode=max \
            --load \
            "$FOLDER"
        rm -rf $CACHE_DIR
        mv $CACHE_DIR-new $CACHE_DIR
    fi
    popd
}

docker_build_cached "aixcc-target-harness-splitter" "$(realpath "$SCRIPT_DIR/../../../target-harness-splitter")"
docker_build_cached "aixcc-aflplusplus" "$(realpath "$SCRIPT_DIR/../../")"
