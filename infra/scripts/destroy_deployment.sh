#!/bin/bash
set -xe

cd $(dirname $0)/..

set +x
. tmp/.env
set -x

pushd tf

if [ ! -z "$1" ]; then
    CURRENT_WORKSPACE=$1
    terraform init \
      -reconfigure \
      -backend-config="key=terraform.tfstate.$CURRENT_WORKSPACE"
    terraform workspace select $CURRENT_WORKSPACE || terraform workspace new $CURRENT_WORKSPACE
else
    CURRENT_WORKSPACE=$(terraform workspace show)
fi

popd

./scripts/destroy.sh $@

# If default error out
if [ "$CURRENT_WORKSPACE" != "default" ]; then
    terraform workspace select default || true
    terraform workspace delete $CURRENT_WORKSPACE || true
fi


# TODO delete statefile from azure storage account
