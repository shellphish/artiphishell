#!/bin/bash

set -xe

SCRIPT_DIR=$(realpath $(dirname $0))

cd $SCRIPT_DIR/..

. tmp/.k8-env

az acr login --name $LOGIN_SERVER