#!/bin/bash
#
export TARGETDIR=$1
export ROOT=$(realpath $(pwd))
set -e
set -x

cd "$TARGETDIR"
# cat ${ROOT}/Dockerfile.extensions >> Dockerfile
# cp ${ROOT}/.env.docker .env.docker
mkdir -p container_scripts
sed -i '/DOCKER_IMAGE_NAME/d' ${TARGETDIR}/.env.project
echo 'DOCKER_IMAGE_NAME=ghcr.io/aixcc-sc/challenge-004-nginx-cp-grammar-guy-target' >> ${TARGETDIR}/.env.project
cp ${ROOT}/generic_harness.c container_scripts/generic_harness.c
docker build -t ghcr.io/aixcc-sc/challenge-004-nginx-cp-grammar-guy-target .


cd "$TARGETDIR"  && ./run.sh build

