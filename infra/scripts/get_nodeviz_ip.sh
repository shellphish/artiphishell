#!/bin/bash

cd $(dirname $0)/..

set -ex

#set +x
#. tmp/.env
#set -x

#timeout 20 scripts/access_k8.sh 1>/dev/null

# Get the public IP of the API service
while [ -z "$(kubectl get service node-viz -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null)" ]; do
  sleep 5
done

NODEVIZ_IP=$(kubectl get service node-viz -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
echo $NODEVIZ_IP
