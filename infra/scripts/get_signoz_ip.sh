#!/bin/bash

cd $(dirname $0)/..

set -ex
# Get the public IP of the API service
while [ -z "$(kubectl get service aixcc-server-infra -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null)" ]; do
  sleep 5
done

SIGNOZ_IP=$(kubectl get service aixcc-server-infra -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
echo $SIGNOZ_IP
