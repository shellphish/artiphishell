#!/bin/bash

set -ex

cd $(dirname $0)/..

set +x
. tmp/.env
set -x

API_POD=$(kubectl get pod -l app.kubernetes.io/name=api -o jsonpath='{.items[0].metadata.name}')

kubectl exec -it $API_POD -- /bin/bash
