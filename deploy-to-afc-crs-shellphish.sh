#!/bin/bash

set -x
ARTIPHISHELL_DIR=$(realpath $(pwd))

rm -rf ../afc-crs-shellphish-auto-update
cd ../
git clone https://github.com/aixcc-finals/afc-crs-shellphish.git afc-crs-shellphish-auto-update
cd afc-crs-shellphish-auto-update
git reset --hard 0668ca5d1c3ec1197355192e3fad9833145d3d05
git clean -fd
rsync --checksum --exclude=.git --exclude=.github -ra $ARTIPHISHELL_DIR/ ./
git add .
git add -f components/target-identifier/targets/
git add -f services/*/docker-compose.yaml
git add -f libs/agentlib/docker-compose.yaml
git commit -m "Update ARTIPHISHELL in AFC CRS Shellphish"

