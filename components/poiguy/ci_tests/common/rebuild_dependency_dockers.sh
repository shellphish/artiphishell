#!/bin/bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
set -ex
(
    docker pull ghcr.io/shellphish-support-syndicate/aixcc-dependencies-base && \
    docker tag ghcr.io/shellphish-support-syndicate/aixcc-dependencies-base aixcc-dependencies-base && \
    docker pull ghcr.io/shellphish-support-syndicate/aixcc-component-base && \
    docker tag ghcr.io/shellphish-support-syndicate/aixcc-component-base aixcc-component-base
)

(
    CACHE_DIR="/tmp/cache/docker-cache/poiguy"
    mkdir -p $CACHE_DIR
    pushd "${SCRIPT_DIR}/../../"
    if [ ! -z "$ACT" ] || [ -z "$GITHUB_ACTIONS" ] || [ "$RUNNER_ENVIRONMENT" = "self-hosted" ]; then
        docker build -t aixcc-poi-guy .
    else
        docker buildx build \
            --tag aixcc-poi-guy \
            --build-arg IMAGE_PREFIX=ghcr.io/shellphish-support-syndicate/ \
            --cache-from type=local,src=$CACHE_DIR \
            --cache-to type=local,dest=$CACHE_DIR-new,mode=max \
            --load \
            .
        rm -rf $CACHE_DIR
        mv $CACHE_DIR-new $CACHE_DIR
    fi
    popd
)
