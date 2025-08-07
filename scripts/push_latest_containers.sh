#!/usr/bin/env bash

CURRENT_DIR=$(dirname $(realpath $0))
$CURRENT_DIR/../pipelines/local_run/rebuild_local.sh remote
for container in $(docker image ls | grep 'aixcc-sc/asc-crs-shellphish' | awk '{print $1}' | sort | uniq);
do
    docker push $container;
done