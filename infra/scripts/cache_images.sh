#!/bin/bash

set -ex

cd $(dirname $0)/..

./scripts/access_k8.sh

if [ -f ./tmp/.k8-env ]; then
  . ./tmp/.k8-env
else
  pushd ./tf
  RG=$(terraform output -raw resource_group_name)
  K8_NAME=$(terraform output -raw kubernetes_cluster_name)
  LOGIN_SERVER=$(terraform output -raw acr_login_server)
  popd
fi

TAG_VER=v1.0.0

function cache_shellphish_image() {
    # We do not force as this is just an optimization and these may be out of date
    az acr import \
      -g $RG \
      --name $LOGIN_SERVER \
      --source artiphishell.azurecr.io/$1 \
      --image $1 \
      --no-wait
    set +x
    echo "📦 Cached $1:${TAG_VER} in $LOGIN_SERVER"
}

function cache_aixcc_image() {
    az acr import \
      -g $RG \
      --name $LOGIN_SERVER \
      --source ghcr.io/aixcc-finals/$1:${TAG_VER} \
      --image $1:${TAG_VER} \
      --force --no-wait
    set +x
    echo "📦 Cached $1:${TAG_VER} in $LOGIN_SERVER"
}

function cache_dockerhub_image() {
    name=$(basename $1)
    az acr import \
      -g $RG \
      --name $LOGIN_SERVER \
      --source docker.io/$1 \
      --image $name \
      --force --no-wait
    set +x
    echo "📦 Cached $name in $LOGIN_SERVER"
}

cache_shellphish_image oss-fuzz-instrumentation-prebuild-shellphish_aflpp:latest &
cache_shellphish_image oss-fuzz-instrumentation-prebuild-aflrun:latest &
cache_shellphish_image oss-fuzz-instrumentation-prebuild-shellphish_codeql:latest &
cache_shellphish_image oss-fuzz-instrumentation-prebuild-shellphish_wllvm_bear:latest &

cache_aixcc_image base-runner &
cache_aixcc_image base-builder &
cache_aixcc_image base-clang &
cache_aixcc_image base-builder-jvm &
cache_aixcc_image base-runner-debug &
cache_aixcc_image base-image &

# A few of these are not in the background to help deal with rate limiting of dockerhub

cache_dockerhub_image library/docker:28-dind &
sleep 5
cache_dockerhub_image clickhouse/clickhouse-server:24.1.2-alpine &
sleep 5
cache_dockerhub_image signoz/signoz-schema-migrator:0.111.24
sleep 5
cache_dockerhub_image gliderlabs/logspout:v3.2.14 &
sleep 5
cache_dockerhub_image signoz/signoz-otel-collector:0.111.26 &
sleep 5
cache_dockerhub_image signoz/frontend:0.71.0 
sleep 5
cache_dockerhub_image signoz/query-service:0.71.0 &
sleep 5
cache_dockerhub_image signoz/alertmanager:0.23.7 &
sleep 5
cache_dockerhub_image bitnami/zookeeper:3.7.1 
sleep 5

wait