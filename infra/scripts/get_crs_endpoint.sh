#!/bin/bash

cd $(dirname $0)/..

set -e

set +x
. tmp/.env

if [ -f ./tmp/.k8-env ]; then
  . ./tmp/.k8-env
else
  pushd ./tf > /dev/null
  RG=$(terraform output -raw resource_group_name)
  K8_NAME=$(terraform output -raw kubernetes_cluster_name)
  DNS_NAME=$(terraform output -raw dns_name)
  popd > /dev/null
fi

echo "https://$DNS_NAME/"
