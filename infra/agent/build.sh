#!/bin/bash

cd $(dirname $0)

set -ex

export AGENT_BUILD_DIR=$(pwd)
export ROOT=$(realpath $(pwd)/../..)

#export EXTERNAL_REGISTRY="${EXTERNAL_REGISTRY:-ghcr.io/shellphish-support-syndicate}"
export EXTERNAL_REGISTRY="${EXTERNAL_REGISTRY:-artiphishell.azurecr.io}"

cp $ROOT/.dockerignore $ROOT/.dockerignore.bak
cp .dockerignore $ROOT/.dockerignore

function cleanup() {
    rm $ROOT/.dockerignore -f || true
    mv $ROOT/.dockerignore.bak $ROOT/.dockerignore || true
    mv $ROOT/components/aflplusplus/pipeline.yaml.bak $ROOT/components/aflplusplus/pipeline.yaml || true
    mv $ROOT/components/jazzer/pipeline.yaml.bak $ROOT/components/jazzer/pipeline.yaml || true
    mv $ROOT/components/aflrun/pipeline.yaml.bak $ROOT/components/aflrun/pipeline.yaml || true
}

trap cleanup EXIT

export IMAGE_NAME="$EXTERNAL_REGISTRY/aixcc-pdt-agent:latest"

if [ -z "$MAX_FUZZERS" ]; then
    # 1 core each
    MAX_FUZZERS=50
fi

if [ -z "$MAX_SARIF_FUZZERS" ]; then
    MAX_SARIF_FUZZERS=2
fi

cp $ROOT/components/aflplusplus/pipeline.yaml $ROOT/components/aflplusplus/pipeline.yaml.bak
# Update max_replicas in pipeline.yaml
sed -i 's/.*VAR_MAX_FUZZERS.*/    max_concurrent_jobs: '$MAX_FUZZERS'/' $ROOT/components/aflplusplus/pipeline.yaml

cp $ROOT/components/jazzer/pipeline.yaml $ROOT/components/jazzer/pipeline.yaml.bak
# Update max_replicas in pipeline.yaml
sed -i 's/.*VAR_MAX_FUZZERS.*/    max_concurrent_jobs: '$MAX_FUZZERS'/' $ROOT/components/jazzer/pipeline.yaml

cp $ROOT/components/aflrun/pipeline.yaml $ROOT/components/aflrun/pipeline.yaml.bak
# Update max_replicas in pipeline.yaml
sed -i 's/.*VAR_MAX_SARIF_FUZZERS.*/    max_concurrent_jobs: '$MAX_SARIF_FUZZERS'/' $ROOT/components/aflrun/pipeline.yaml

docker build \
    -t $IMAGE_NAME \
    -f $AGENT_BUILD_DIR/Dockerfile \
    --build-arg IMAGE_PREFIX=$EXTERNAL_REGISTRY/ \
    $ROOT $1