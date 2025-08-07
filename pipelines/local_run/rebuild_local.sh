#!/usr/bin/env bash

set -ex

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
SHELLPHISH_CRS_DIR=$(realpath $SCRIPT_DIR/../../)
pushd $SHELLPHISH_CRS_DIR
echo $PWD
if [ "$1" == 'remote' ]; then
    export IMAGE_PREFIX="${IMAGE_PREFIX:-ghcr.io/shellphish-support-syndicate/}"
    PUSH="--push"
    ./scripts/generate_local_docker_compose.sh > ./docker-compose.yaml
    # ./crs/generate_docker_compose.sh > ./docker-compose.yaml
    sed -i 's/ghcr\.io\/shellphish-support-syndicate\//ghcr\.io\/aixcc-sc\/asc-crs-shellphish\//g' ./docker-compose.yaml
else
    export IMAGE_PREFIX=""
    PUSH=""
    ./scripts/generate_local_docker_compose.sh > ./docker-compose.yaml
    # ./crs/generate_docker_compose.sh > ./docker-compose.yaml
    sed -i 's/ghcr\.io\/shellphish-support-syndicate\///g' ./docker-compose.yaml
fi

docker build $ADDITIONAL_DOCKER_ARGS -t ${IMAGE_PREFIX}aixcc-dependencies-base:latest ./pipelines/components/common/base -f ./pipelines/components/common/base/Dockerfile.dependencies-base $PUSH
docker build $ADDITIONAL_DOCKER_ARGS -t ${IMAGE_PREFIX}aixcc-component-base:latest ./pipelines/components/common/base -f ./pipelines/components/common/base/Dockerfile.component-base --build-arg IMAGE_PREFIX=${IMAGE_PREFIX} $PUSH
if [ "$1" == "remote" ]; then
    docker build $ADDITIONAL_DOCKER_ARGS -t ${IMAGE_PREFIX}aixcc-leader:latest ./pipelines -f ./pipelines/meta-components/leader-scripts/Dockerfile --build-arg IMAGE_PREFIX=${IMAGE_PREFIX} $PUSH
fi
#docker build -t image-aixcc-opwnai-base:latest ./pipelines/ -f ./pipelines/components/common/opwnai/Dockerfile

docker compose -f ./docker-compose.yaml --profile local build $ADDITIONAL_DOCKER_ARGS
if [[ -n "$PUSH" ]]; then
    docker compose -f ./docker-compose.yaml --profile local push -q
fi
rm docker-compose.yaml
popd
