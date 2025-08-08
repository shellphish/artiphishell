#!/bin/bash
set -ex

SCRIPT_DIR=$(dirname $(realpath $0))

export EXTERNAL_REGISTRY="${EXTERNAL_REGISTRY:-artiphishell.azurecr.io}"

pushd $SCRIPT_DIR
    # Loop through all services
    for service_dir in services/*/; do
        service_name=$(basename $service_dir)
        echo "######### BUILD ${service_name^^} #########"
        
        pushd $service_dir
            NAME="aixcc-$service_name"
            IMAGE_NAME="$EXTERNAL_REGISTRY/$NAME:latest"
            DOCKERFILE="Dockerfile"
            # Check if we're building for Kubernetes (Azure)
            if [[ "$service_name" == "otel-collector" ]]; then
                if [[ "$EXTERNAL_REGISTRY" == *"azure"* ]]; then
                    DOCKERFILE="Dockerfile.kube"
                else
                    DOCKERFILE="Dockerfile.local"
                fi
            fi
            docker build -t ${IMAGE_NAME} . -f $DOCKERFILE --build-arg IMAGE_PREFIX=$EXTERNAL_REGISTRY/ $1
        popd
    done
popd
