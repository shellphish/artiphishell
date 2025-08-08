#!/bin/bash
umask 022

set -ex
SCRIPT_DIR=$(realpath $(dirname $0))
ROOT_DIR=$(realpath $SCRIPT_DIR/../../..)

cd $ROOT_DIR

mkdir -p /backup/k8s_info

timestamp=$(date +%s)

BACKUP_DIR="/backup/k8s_info/${timestamp}"
mkdir -p $BACKUP_DIR

echo "=== Backing up k8s metadata ==="

(timeout 300 kubectl get pods -o wide > $BACKUP_DIR/k8s_pods.txt || true)
(timeout 300 kubectl describe pods > $BACKUP_DIR/k8s_describe_pods.txt || true)
(timeout 300 kubectl describe nodes > $BACKUP_DIR/k8s_describe_nodes.txt || true)
(timeout 300 kubectl get services -o wide > $BACKUP_DIR/k8s_services.txt || true)
(timeout 300 kubectl get events --all-namespaces > $BACKUP_DIR/k8s_events.txt || true)
(timeout 300 kubectl describe configmap cluster-autoscaler-status -n kube-system > $BACKUP_DIR/autoscaler_status.txt || true)
(
    pushd /app
    pd status -j > $BACKUP_DIR/pd_status.txt
    popd
) || true

wait