#!/bin/bash

cd $(dirname $0)/..

set -xe

set +x
. tmp/.env
set -x

if [[ "$*" =~ "--tailscale" ]]; then
    ./k8/charts/tailscale/destroy.sh || true
fi

pushd k8/charts/artiphishell

helm uninstall artiphishell || true

kubectl delete all --all -n default || true
