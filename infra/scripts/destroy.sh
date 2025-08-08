#!/bin/bash

set -xe

cd $(dirname $0)/..

set +x
. tmp/.env
set -x

rm -f tmp/.k8-env

pwd

if [[ ! "$*" =~ "--fast" ]]; then

./scripts/stop_helm.sh --tailscale || true

fi

pushd tf
ARGS=""
if [ ! -z "$AUTO_APPROVE" ]; then
    ARGS="-auto-approve"
fi

set -o pipefail

if terraform refresh -lock=false 2>&1 | tee /tmp/refresh.log; then
    echo "refreshed"
else
    if grep 'alpha numeric characters' /tmp/refresh.log; then
        echo "Deployment is invalid, nothing to destroy"
        exit 0
    fi
    if grep 'only contain alphabet' /tmp/refresh.log; then
        echo "Deployment is invalid, nothing to destroy"
        exit 0
    fi
fi

set +o pipefail


RG=$(terraform output -raw resource_group_name)

if [[ "$*" =~ "--fast" ]]; then
    # Use azure to just delete the entire resource group
    az group delete --name $RG --yes || true
    exit 0
fi

# Get list of public ips
PUBLIC_IPS=$(terraform output -json public_ip_names | jq -cr '.[]')
CLUSTER_RG=$(terraform output -raw cluster_rg)

terraform state rm 'azurerm_public_ip.api_ip' || true
terraform state rm 'azurerm_public_ip.viz_ip' || true
terraform state rm 'azurerm_public_ip.nodeviz_ip' || true

# Delete each public ip
for IP in $PUBLIC_IPS; do
    az network public-ip update --name $IP --resource-group $CLUSTER_RG --allocation-method Static --remove "ipConfiguration" || true
done


terraform destroy $ARGS -lock=false --auto-approve
popd
