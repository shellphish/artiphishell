#!/bin/bash

set -e

cd $(dirname $0)

mkdir -p ./tmp

if [ -z "$TS_CLIENT_ID" ]; then
    echo "❌ Error: TS_CLIENT_ID is not set"
    exit 1
fi
if [ -z "$TS_CLIENT_SECRET" ]; then
    echo "❌ Error: TS_CLIENT_SECRET is not set"
    exit 1
fi
if [ -z "$TS_OP_TAG" ]; then
    echo "❌ Error: TS_OP_TAG is not set"
    exit 1
fi

envsubst <./operator/operator.template >./operator/operator.yaml

kubectl apply -k ./operator/
kubectl apply -k ./dns/

echo -e "📦  Waiting for the service nameserver to exist"

timeout 5m bash -c "until kubectl get svc -n tailscale nameserver > /dev/null 2>&1; do sleep 1; done" || echo -e "🤡  Error: nameserver failed to exist within 5 minutes"

echo -e "🏷️  Waiting for nameserver to have a valid ClusterIP"
timeout 5m bash -c "until kubectl get svc -n tailscale nameserver -o jsonpath='{.spec.clusterIP}' | grep -v '<none>' > /dev/null 2>&1; do sleep 1; done" || echo -e "🤡  Error: nameserver failed to obtain a valid CLusterIP within 5 minutes"

export TS_DNS_IP=$(kubectl get svc -n tailscale nameserver -o jsonpath='{.spec.clusterIP}')

envsubst <./coredns/coredns-custom.template >./coredns/coredns-custom.yaml

kubectl apply -k ./coredns/

kubectl apply -k ./connections/

echo -e "🚪 Waiting for ingress hostname DNS registration"


INGRESS_HOSTNAME=$(kubectl get ingress api -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')

echo -e "🛜  Your ingress DNS hostname is $INGRESS_HOSTNAME"


