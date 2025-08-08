#!/bin/bash

cd $(dirname $0)/..

set -e
set +x

. tmp/.env

# check if k8 is installed
if ! command -v kubectl &> /dev/null; then
    az aks install-cli
fi

pushd tf

if [ -f ../tmp/.k8-env ]; then
  . ../tmp/.k8-env
  if [ -z "$K8_NAME" ]; then
    rm ../tmp/.k8-env
  fi
else
  RG=$(terraform output -raw resource_group_name)
  K8_NAME=$(terraform output -raw kubernetes_cluster_name)
fi

popd

timeout 20 az aks get-credentials --resource-group $RG --name $K8_NAME || (
  sleep 20 &&
  timeout 20 az aks get-credentials --resource-group $RG --name $K8_NAME
)

#kubectl get nodes