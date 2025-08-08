#!/bin/bash
#
export TARGETDIR=$1
export BUILDFLAG=$2

set -e
set -x

cd "$TARGETDIR"
cat /shellphish/Dockerfile.extensions >> Dockerfile
cp /shellphish/.env.docker .env.docker
mkdir -p container_scripts
cp generic_harness.c container_scripts/generic_harness.c

docker build -t $(yq "grammar-guy-target" ./project.yaml) .
./run.sh build

