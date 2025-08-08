#!/bin/bash

if [ ! -z "$USE_LOCAL_REGISTRY" ]; then
    export OUTPUT_IMAGE_PREFIX=$USE_LOCAL_REGISTRY
    export DO_PUSH=true
fi

pull_and_tag() {
    docker pull $1
    IMG=$(basename $1)
    docker tag $1 $OUTPUT_IMAGE_PREFIX$IMG
    if [ ! -z "$DO_PUSH" ]; then
        docker push $OUTPUT_IMAGE_PREFIX$IMG
    fi
}

pull_and_tag ghcr.io/shellphish-support-syndicate/aixcc-dependencies-base:latest
pull_and_tag ghcr.io/shellphish-support-syndicate/aixcc-component-base:latest
