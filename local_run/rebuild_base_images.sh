#!/usr/bin/env bash

set -ex

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
SHELLPHISH_CRS_DIR=$(realpath $SCRIPT_DIR/../)
pushd $SHELLPHISH_CRS_DIR
echo $PWD
if [ "$1" == 'remote' ]; then
    export IMAGE_PREFIX="${IMAGE_PREFIX:-ghcr.io/shellphish-support-syndicate/}"
    PUSH="--push"
else
    export IMAGE_PREFIX="ghcr.io/shellphish-support-syndicate/"
    PUSH=""
fi

# TODO build these again
docker build $ADDITIONAL_DOCKER_ARGS -t ${IMAGE_PREFIX}aixcc-dependencies-base:latest ./ -f ./docker/Dockerfile.dependencies-base $PUSH
# docker pull ghcr.io/shellphish-support-syndicate/aixcc-dependencies-base:latest
docker tag ${IMAGE_PREFIX}aixcc-dependencies-base:latest aixcc-dependencies-base:latest

docker build $ADDITIONAL_DOCKER_ARGS -t ${IMAGE_PREFIX}aixcc-component-base:latest ./ -f ./docker/Dockerfile.component-base --build-arg IMAGE_PREFIX=${IMAGE_PREFIX} $PUSH
# docker pull ghcr.io/shellphish-support-syndicate/aixcc-component-base:latest
docker tag ${IMAGE_PREFIX}aixcc-component-base:latest aixcc-component-base:latest

docker build $ADDITIONAL_DOCKER_ARGS -t ${IMAGE_PREFIX}aixcc-data:latest ./ -f ./docker/Dockerfile.data $PUSH
docker tag ${IMAGE_PREFIX}aixcc-data:latest aixcc-data:latest

mv ./.dockerignore ./.dockerignore.bak || true
docker build $ADDITIONAL_DOCKER_ARGS -t ${IMAGE_PREFIX}aixcc-libs:latest ./libs -f ./libs/Dockerfile --build-arg IMAGE_PREFIX=${IMAGE_PREFIX} $PUSH
docker tag ${IMAGE_PREFIX}aixcc-libs:latest aixcc-libs:latest
mv ./.dockerignore.bak ./.dockerignore || true

docker build $ADDITIONAL_DOCKER_ARGS -t ${IMAGE_PREFIX}aixcc-afc-competition-api:latest ./aixcc-infra/aixcc-afc-competition-api -f ./aixcc-infra/aixcc-afc-competition-api/Dockerfile --build-arg IMAGE_PREFIX=${IMAGE_PREFIX} $PUSH
docker tag ${IMAGE_PREFIX}aixcc-afc-competition-api:latest aixcc-afc-competition-api:latest

popd