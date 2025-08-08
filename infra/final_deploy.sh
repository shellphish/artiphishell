#!/bin/bash

set -ex

INFRA_DIR=$(realpath $(dirname $0))
cd $INFRA_DIR

# Check if first argument exists and is not a flag
# Use regex to ensure it doesn't start with -- and doesn't contain any spaces
if [ ! -z "$1" ] && [[ ! "$1" =~ ^-- ]] && [[ ! "$1" =~ [[:space:]] ]]; then
    export DEPLOYMENT_NAME=$1
    # Shift the first argument so it's not processed again
    shift
fi

. $INFRA_DIR/final.secrets

export TS_CLIENT_ID='kxXhutTgZ611CNTRL'
export TS_OP_TAG='tag:crs-binary-blade'

# CHANGE AZURE_USER TO GENERATE A NEW SECURITY PRINCIPAL IF AZURE ERROR IS ENCOUNTERED
export AZURE_USER='finalf'
export TF_VAR_ARM_TENANT_ID='c67d49bd-f3ec-4c7f-b9ec-653480365699'
export TF_VAR_ARM_SUBSCRIPTION_ID='3b953cdb-4a0e-4f31-a866-151e2c1ece7d'
export TF_VAR_ARM_CLIENT_ID=''
export TF_VAR_ARM_RESOURCE_GROUP='ARTIPHISHELL-PROD-AFC'
export TF_VAR_ARM_STORAGE_ACCOUNT='artiphishellprodafc'

#export CRS_API_HOSTNAME='binary-blade.tail7e9b4c.ts.net'
export CRS_API_HOSTNAME='binary-blade-final.tail7e9b4c.ts.net'
export CRS_API_URL="https://$CRS_API_HOSTNAME"
export CRS_KEY_ID='c0c3003b-2a83-4a52-8a76-95a0a95e710f'

export COMPETITION_API_KEY_ID='3020f48e-8999-4a3e-a238-afe4d187a566'
export COMPETITION_API_URL='https://api.tail7e9b4c.ts.net'

export OTEL_EXPORTER_OTLP_ENDPOINT="https://otel.binary-blade.aixcc.tech:443"
export OTEL_EXPORTER_OTLP_PROTOCOL=grpc

export TS_DNS_IP='10.0.164.203'

# ==== CONFIG ====
set -x 
. $INFRA_DIR/final.env

$INFRA_DIR/scripts/do_offical_deployment.sh $@