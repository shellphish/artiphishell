#!/bin/bash

set -ex

cd "$(dirname "$0")"

export 'ANALYSIS_GRAPH_BOLT_URL=bolt://neo4j:artiphishell@localhost:7687'
export 'FUNC_RESOLVER_URL=http://localhost:4033'

if docker inspect aixcc-component-base:latest; then
    echo
else
    az acr login -n artiphishelltiny.azurecr.io
    docker pull artiphishelltiny.azurecr.io/aixcc-dependencies-base:latest
    docker tag artiphishelltiny.azurecr.io/aixcc-dependencies-base:latest aixcc-dependencies-base:latest
    docker pull artiphishelltiny.azurecr.io/aixcc-component-base:latest
    docker tag artiphishelltiny.azurecr.io/aixcc-component-base:latest aixcc-component-base:latest
fi

docker compose build
docker compose up --force-recreate --remove-orphans -d -t0

sleep 5

function-resolver-upload-backup ./

docker compose logs -f


