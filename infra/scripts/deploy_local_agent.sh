#!/bin/bash

# Use this script to relatively quickly re-deploy your local copy of the pydatatask agent
# To your current kubernetes cluster

# WARNING: WILL DELETE EXISTING PODS

set -ex

cd $(dirname $0)/../..

(timeout 30 ./infra/scripts/stop_helm.sh &)

az acr login -n artiphishell
./infra/agent/build.sh
./infra/api/build.sh

docker push artiphishell.azurecr.io/aixcc-pdt-agent:latest 
docker push artiphishell.azurecr.io/aixcc-crs-api:latest 

wait



./infra/scripts/restart_helm.sh --skiptf