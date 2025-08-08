#!/bin/bash

cd $(dirname $0)/..

set -e

set +x
. tmp/.env
set -x

timeout 20 scripts/access_k8.sh 1>/dev/null

set +x

# Get the public IP of the API service
while true; do
  API_IP=$(kubectl get service ci-api -o jsonpath='{.spec.clusterIP}')
  if [ ! -z "$API_IP" ]; then
    break
  fi
done

echo $API_IP
