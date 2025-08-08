#!/bin/bash

cd $(dirname $0)/..

set -xe

set +x
. tmp/.env
set -x

az storage account create \
    --resource-group $AZURE_RG \
    --name $AZURE_STORAGE_ACCOUNT \
    --sku Standard_LRS \
    --encryption-services blob

az storage container create \
    --name $TARGET_STORAGE_CONTAINER \
    --account-name $AZURE_STORAGE_ACCOUNT \
    --auth-mode login

az storage container create \
    --name $TARGET_STORAGE_CONTAINER \
    --account-name $AZURE_STORAGE_ACCOUNT \
    --auth-mode login
