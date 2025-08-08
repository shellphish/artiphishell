#!/bin/bash

set -ex

# Install dependencies

cd $(dirname $0)/..

sudo apt-get update -y && sudo apt-get install -y git unzip tar python3 python3-dev g++-11

export CC=gcc-11
export CXX=g++-11

#CACHE_DIR="/tmp/cache/docker-cache/patchery"
#mkdir -p $CACHE_DIR
## if ACT is set or GITHUB_ACTIONS is not set then we are running locally
#if [ ! -z "$ACT" ] || [ -z "$GITHUB_ACTIONS" ] || [ "$RUNNER_ENVIRONMENT" = "self-hosted" ]; then
#  docker build \
#    --file ./Dockerfile \
#    --tag aixcc-patchery \
#    --build-arg IMAGE_PREFIX=ghcr.io/shellphish-support-syndicate/ \
#    .
#else
#  # Inside github actions we need to use /tmp/cache to save the cache
#  docker buildx build \
#    --file ./Dockerfile \
#    --tag aixcc-patchery \
#    --build-arg IMAGE_PREFIX=ghcr.io/shellphish-support-syndicate/ \
#    --cache-from type=local,src=$CACHE_DIR \
#    --cache-to type=local,dest=$CACHE_DIR-new,mode=max \
#    --load \
#    .
#  rm -rf $CACHE_DIR
#  mv $CACHE_DIR-new $CACHE_DIR
#fi

# debugging env
export LOG_LLM=0
export LOG_LEVEL=WARNING
export PYTHONBREAKPOINT=ipdb.set_trace
python -m pip install --upgrade pip

#install dependencies
pushd ../../libs/libcodeql
    pip install -e .
popd

pushd ../../libs/analysis-graph
    pip install -e .
popd

pushd ../../libs/kumu-shi
    pip install -e .
popd

pushd ../../libs/crs-utils
    pip install -e .
popd

#pip install ./libs/clang-indexer
pip install .[test]
ls -la ./tests/aicc_testing/mock_cp/backup-mock-cp-13883965678

# Pytest
export ON_CI=true
#export LITELLM_KEY=no
#export AIXCC_LITELLM_HOSTNAME=no
stdbuf -o0 -e0 pytest --log-cli-level=DEBUG --log-level=DEBUG -s --capture=no -v ./tests/test_aicc.py

