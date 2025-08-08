#!/bin/bash

cd $(dirname $0)/..

set -e
set +x

. tmp/.env

./scripts/access_k8.sh

pushd tf

if [ -f ../tmp/.k8-env ]; then
  . ../tmp/.k8-env
else
  pushd ./tf
  RG=$(terraform output -raw resource_group_name)
  K8_NAME=$(terraform output -raw kubernetes_cluster_name)
  popd
fi

popd

set -x

ID=$(az aks show --resource-group $RG --name $K8_NAME --query id -o tsv)

az monitor log-analytics workspace create --resource-group $RG --workspace-name clusterlogs || true

WORKSPACE_ID=$(az monitor log-analytics workspace show --resource-group $RG --workspace-name clusterlogs --query id -o tsv)

az monitor diagnostic-settings create --resource "$ID" --name myMonitoringSettings --workspace "$WORKSPACE_ID" --logs '[{"category": "kube-audit", "enabled": true}]'

az aks enable-addons -a monitoring -n $K8_NAME -g $RG --workspace-resource-id "$WORKSPACE_ID"


