#!/bin/bash

set -x

cd $(dirname $0)/../../..

./scripts/access_k8.sh || true

kubectl delete -k k8/charts/tailscale/connections || true

timeout 2m bash -c "until kubectl get statefulset -n tailscale -l tailscale.com/parent-resource=api,tailscale.com/parent-resource-ns=api 2>&1 | grep -q 'No resources found'; do sleep 1; done" || echo -e "${RED}Error: StatefulSet cleanup timed out after 2 minutes${NC}"

kubectl delete -k k8/charts/tailscale/coredns/ || true
kubectl delete -k k8/charts/tailscale/dns/ || true
kubectl delete -k k8/charts/tailscale/operator/ || true

