#!/bin/bash

set -eux

export EXTERNAL_REGISTRY=${EXTERNAL_REGISTRY:-}
export PUSH=${PUSH:-}

if [ ! -z "$PUSH" ]; then
    export DOCKER_IMAGE_PREFIX="$EXTERNAL_REGISTRY/"
else
    export DOCKER_IMAGE_PREFIX=""
fi
 
# this must be unset for this command to work, identifying this as running outside of the k8s cluster
unset IN_K8S

INSTRUMENTATIONS_TO_PREBUILD=(
    aflrun
    shellphish_aflpp
    clang_indexer
    griller
    griller_flag
    shellphish_codeql
    coverage_fast
    discovery_guy
    shellphish_jazzer
    shellphish_libfuzzer
)

for inst in "${INSTRUMENTATIONS_TO_PREBUILD[@]}"; do
    oss-fuzz-prebuild-instrumentation-image $PUSH --instrumentation $inst
done
