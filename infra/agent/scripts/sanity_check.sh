#!/bin/bash

set -ex

export LITELLM_KEY='sk-artiphishell-da-best!!!'

if [ -z "$AIXCC_LITELLM_HOSTNAME" ]; then
    echo "AIXCC_LITELLM_HOSTNAME was not set! Defaulting to http://litellm:4000/"
    export AIXCC_LITELLM_HOSTNAME='http://litellm:4000/'
fi

export DOCKER_HOST=tcp://docker-builder:2375

export CODEQL_SERVER_URL=http://codeql:$CODEQL_SERVICE_PORT

export ANALYSIS_GRAPH_BOLT_URL="bolt://neo4j:$AGENT_SECRET@analysisgraph:$ANALYSISGRAPH_SERVICE_PORT"
export PERMANENCE_SERVER_URL="http://permanence:$PERMANENCE_SERVICE_PORT"
export PERMANENCE_SERVER_GLOBAL_URL=""

export LANG_SERVER_URL="http://langserver:$LANGSERVER_SERVICE_PORT"
export FUNC_RESOLVER_URL="http://functionresolver:$FUNCTIONRESOLVER_SERVICE_PORT"

export INFLUXDB_URL="http://telemetrydb:$TELEMETRYDB_SERVICE_PORT"
export INFLUXDB_TOKEN="shellphish-influxdb-token"
export INFLUXDB_BUCKET="artiphishell"
export INFLUXDB_ORG="artiphishell"

echo "=== CHECKING NODE LOCAL DOCKER DAEMON IS RUNNING ==="

if [ -z "$CRS_IMAGE_REGISTRY" ]; then
    echo "❌ CRS_IMAGE_REGISTRY is not set!"
    exit 1
fi

docker info
docker pull ubuntu:latest

docker login $CRS_IMAGE_REGISTRY -u "$ACR_USERNAME" -p "$ACR_PASSWORD"

docker tag ubuntu:latest $CRS_IMAGE_REGISTRY/ubuntu:latest
docker push $CRS_IMAGE_REGISTRY/ubuntu:latest
docker pull $CRS_IMAGE_REGISTRY/ubuntu:latest

echo "=== CHECKING IF TAILSCALE IS WORKING ==="

curl -v https://echo.tail7e9b4c.ts.net | tee /tmp/res
grep "Request served" /tmp/res

echo "=== CHECKING COMPETITION API IS REACHABLE ==="

curl -v https://api.tail7e9b4c.ts.net/v1/ping | tee /tmp/res
grep "Unauthorized" /tmp/res

echo "=== CHECKING CRS API IS REACHABLE OVER TAILSCALE ==="

curl -v https://binary-blade-final.tail7e9b4c.ts.net/status/ | tee /tmp/res
#grep "200" /tmp/res

echo "=== CHECKING LITELLM IS REACHABLE ==="

if [ "$AIXCC_LITELLM_HOSTNAME" != "http://litellm:4000/" ]; then
    echo "❌ LITELLM_HOSTNAME is not set to http://litellm:4000/"
    exit 1
fi
curl -v ${AIXCC_LITELLM_HOSTNAME%/}/health/readiness -H 'accept: application/json' | jq | tee /tmp/res


echo "=== CHECKING CODEQL SERVER IS REACHABLE ==="
curl -v $CODEQL_SERVER_URL/ping | jq | tee /tmp/res
grep "Not Found" /tmp/res

echo "=== CHECKING PERMANENCE SERVER IS REACHABLE ==="
curl -v $PERMANENCE_SERVER_URL/status -H 'Shellphish-Secret: !!artiphishell!!' | jq | tee /tmp/res
grep "running" /tmp/res

echo "=== CHECKING LANG SERVER IS REACHABLE ==="
curl -v $LANG_SERVER_URL/list_projects | jq | tee /tmp/res
grep "projects" /tmp/res

echo "=== CHECKING FUNCTION RESOLVER IS REACHABLE ==="
curl -v $FUNC_RESOLVER_URL/list_projects | jq | tee /tmp/res
grep "Not Found" /tmp/res

echo "=== TESTING LITELLM API ==="

curl -v -X POST 'http://litellm:4000/chat/completions' \
--header 'Authorization: Bearer sk-artiphishell-da-best!!!' \
--header 'Content-Type: application/json' \
--data-raw '{
    "model": "oai-gpt-4o",
    "messages": [
        {
        "role": "user",
        "content": "Whats the weather like in DC today?"
        }
    ],
    "user": "openai-budget"
}' | jq | tee /tmp/res

curl -v -X POST 'http://litellm:4000/chat/completions' \
--header 'Authorization: Bearer sk-artiphishell-da-best!!!' \
--header 'Content-Type: application/json' \
--data-raw '{
    "model": "claude-3.7-sonnet",
    "messages": [
        {
        "role": "user",
        "content": "Whats the weather like in DC today?"
        }
    ],
    "user": "claude-budget"
}' | jq | tee /tmp/res


echo "✅✅✅✅✅✅✅✅✅✅✅"