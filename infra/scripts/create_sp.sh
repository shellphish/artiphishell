#!/bin/bash

cd $(dirname $0)/..

set -xe

if [ -z "$AZURE_USER" ]; then
    AZURE_USER=$(az ad signed-in-user show --query userPrincipalName -o tsv | cut -d'#' -f1 | tr -cd '[:alnum:]' | cut -c1-6)
fi

mkdir -p tmp

set +x
#TENANT_ID=${TF_VAR_ARM_TENANT_ID:-'c67d49bd-f3ec-4c7f-b9ec-653480365699'}
TENANT_ID=${TF_VAR_ARM_TENANT_ID:-'8ff5baa0-c223-4e08-b3f3-113ca88f371c'}

# DEV SUBSCRIPTION ID
#SUBSCRIPTION_ID=${TF_VAR_ARM_SUBSCRIPTION_ID:-'eb36190a-c4f0-4333-87d5-713e9b02f6a1'}
SUBSCRIPTION_ID=${TF_VAR_ARM_SUBSCRIPTION_ID:-'a807ad5f-e144-461b-bcc3-5df0fe360d4b'}
RESOURCE_GROUP=${TF_VAR_ARM_RESOURCE_GROUP:-'ARTIPHISHELL-PROD-AFC'}
STORAGE_ACCOUNT=${TF_VAR_ARM_STORAGE_ACCOUNT:-'artiphishellprodafc'}

set -x
az account set --subscription $SUBSCRIPTION_ID || true

STORAGE_CONTAINER='tfstate'
TARGET_STORAGE_CONTAINER='targets'

if [ ! -z "$TF_VAR_ARM_CLIENT_ID" ] && [ ! -z "$TF_VAR_ARM_CLIENT_SECRET" ]; then
    CLIENT_ID=$TF_VAR_ARM_CLIENT_ID
    CLIENT_SECRET=$TF_VAR_ARM_CLIENT_SECRET
elif [ ! -z "$AZURE_CLIENT_ID" ] && [ ! -z "$AZURE_CLIENT_SECRET" ]; then
    CLIENT_ID=$AZURE_CLIENT_ID
    CLIENT_SECRET=$AZURE_CLIENT_SECRET
else
    if [ ! -s tmp/sp.json ] || ! jq < tmp/sp.json > /dev/null 2>&1; then
        az ad sp create-for-rbac --name "ARTIPHISHELL-K8-SP-$AZURE_USER" --role Contributor --scopes /subscriptions/$SUBSCRIPTION_ID --output json | tee tmp/sp.json
    fi
    CLIENT_ID=$(jq -c -r '.appId' < tmp/sp.json)
    CLIENT_SECRET=$(jq -c -r '.password' < tmp/sp.json)
fi

if [ "$NO_EXTERNAL_REGISTRY" != 'true' ]; then
    # For CI runs we can access external registry
    # For full game runs, we do not allow it

    if [ ! -s tmp/artiphishell-acr.json ] || ! jq < tmp/artiphishell-acr.json > /dev/null 2>&1; then
        az acr token create \
            --name "ARTIPHISHELL-K8-PUSH-$AZURE_USER" \
            --registry "artiphishell" \
            --output json \
            --scope-map "_repositories_push" | tee tmp/artiphishell-acr.json
    fi

    CI_ACR_USERNAME=$(jq -c -r '.name' < tmp/artiphishell-acr.json)
    CI_ACR_PASSWORD=$(jq -c -r '.credentials.passwords[0].value' < tmp/artiphishell-acr.json)
else
    CI_ACR_USERNAME=''
    CI_ACR_PASSWORD=''
fi

set -x

az group create \
    --name $RESOURCE_GROUP \
    --location "westus"

az storage account create \
    --resource-group $RESOURCE_GROUP \
    --name $STORAGE_ACCOUNT \
    --sku Standard_LRS \
    --encryption-services blob

az storage container create \
    --name $STORAGE_CONTAINER \
    --account-name $STORAGE_ACCOUNT \
    --auth-mode login

az storage container create \
    --name $TARGET_STORAGE_CONTAINER \
    --account-name $STORAGE_ACCOUNT \
    --auth-mode login

if [ ! -s tmp/target-sts-token.json ] || \
   [ $(date -d "$(cat tmp/target-sts-token.json | sed 's/.*se=\([^&]*\).*/\1/' | sed 's/%3A/:/g')" +%s) -lt $(date +%s) ]; then
    az storage container generate-sas \
        --name $TARGET_STORAGE_CONTAINER \
        --account-name $STORAGE_ACCOUNT \
        --permissions acdlrw \
        --expiry $(date -u -d "28 days" '+%Y-%m-%dT%H:%MZ') | tee tmp/target-sts-token.json
fi

TARGET_STS_TOKEN=$(jq -c -r . < tmp/target-sts-token.json)

# Get the storage account connection string
STORAGE_CONNECTION_STRING=$(az storage account show-connection-string \
    --name $STORAGE_ACCOUNT \
    --resource-group $RESOURCE_GROUP \
    --output tsv)


AGENT_SECRET=${AGENT_SECRET:-helloworldpdt}

set +x
cat <<EOF > tmp/.env
export CRS_API_HOSTNAME='$CRS_API_HOSTNAME'
export CRS_KEY_ID='$CRS_KEY_ID'
export CRS_KEY_TOKEN='$CRS_KEY_TOKEN'
export COMPETITION_API_KEY_ID='$COMPETITION_API_KEY_ID'
export COMPETITION_API_KEY_TOKEN='$COMPETITION_API_KEY_TOKEN'
export GHCR_AUTH='$GHCR_AUTH'

export TS_CLIENT_ID='$TS_CLIENT_ID'
export TS_CLIENT_SECRET='$TS_CLIENT_SECRET'
export TS_OP_TAG='$TS_OP_TAG'

export AZURE_USER='$AZURE_USER'
export AZURE_RG='$RESOURCE_GROUP'
export ARM_CLIENT_ID='$CLIENT_ID'
export ARM_CLIENT_SECRET='$CLIENT_SECRET'
export ARM_TENANT_ID='$TENANT_ID'
export ARM_SUBSCRIPTION_ID='$SUBSCRIPTION_ID'
export AZURE_STORAGE_ACCOUNT='$STORAGE_ACCOUNT'
export AZURE_STORAGE_CONTAINER='$STORAGE_CONTAINER'
export TARGET_STORAGE_CONTAINER='$TARGET_STORAGE_CONTAINER'
export TARGET_STS_TOKEN='$TARGET_STS_TOKEN'
export STORAGE_CONNECTION_STRING='$STORAGE_CONNECTION_STRING'

export CI_ACR_USERNAME='$CI_ACR_USERNAME'
export CI_ACR_PASSWORD='$CI_ACR_PASSWORD'
export CI_ACR_SERVER=''
export AGENT_SECRET='$AGENT_SECRET'
EOF

set -x
