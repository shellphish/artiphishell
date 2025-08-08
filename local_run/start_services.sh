#!/bin/bash

set -eux

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
SCRIPT_PARENT_DIR=$(dirname $SCRIPT_DIR)
ARTIPHISHELL_ROOT="$SCRIPT_PARENT_DIR/"
HOST_IP=$(ip route show default | awk '/default/ {print $9}')

# Start CRS API (Must pip install libs/crs-api)
if [ -f $ARTIPHISHELL_ROOT/local_run/.crs-api.pid ]; then
    pkill -P $(cat $ARTIPHISHELL_ROOT/local_run/.crs-api.pid) || true
    kill -9 $(cat $ARTIPHISHELL_ROOT/local_run/.crs-api.pid) || true
    rm $ARTIPHISHELL_ROOT/local_run/.crs-api.pid
fi

if [ "${USE_COMPETITION_SERVICE:-}" = "true" ]; then
  pushd $ARTIPHISHELL_ROOT/aixcc-infra/competition-server

      # These envs will be set in the scantron.yaml file
      export ARTIPHISHELL_API_URL="http://${HOST_IP}:8000"

      # This is the API key for the competition server
      export COMPETITION_SERVER_API_ID="11111111-1111-1111-1111-111111111111"
      export COMPETITION_SERVER_API_KEY="secret"

    #   docker compose down -v || true
      ./build.sh
      docker compose up -d 

      # Wait for the competition server to be ready
      echo "Waiting for competition server to start..."
      while ! docker inspect aixcc-competition-server >/dev/null 2>&1 || [ "$(docker inspect -f '{{.State.Running}}' aixcc-competition-server)" != "true" ]; do
          echo "Competition server not ready yet, waiting 3 seconds..."
          sleep 3
      done
      echo "Competition server is up and running!"
      # This is the API for the competition server
      export COMPETITION_SERVER_URL=http://${HOST_IP}:1323

      # This is the GUI for the competition server
      export COMPETITION_DASHBOARD_URL=http://${HOST_IP}:3301

      # Set the environment variables for our otel collector to hit the signoz otel collector
      export SIGNOZ_OTEL_EXPORTER_OTLP_ENDPOINT=http://${HOST_IP}:4317
      export SIGNOZ_BASIC_AUTH=$(echo -en "${COMPETITION_SERVER_API_ID}:${COMPETITION_SERVER_API_KEY}" | base64 -w 0)

  popd

  serve-crs-api &> $ARTIPHISHELL_ROOT/local_run/.crs-api.log &
  echo "$!" > $ARTIPHISHELL_ROOT/local_run/.crs-api.pid
fi

pushd $ARTIPHISHELL_ROOT/services
    pushd analysis_graph
        docker compose down -v || true
        docker compose up --build -d
        sudo chown -R 7474:7474 ./neo4j_db/ || true
        ANALYSIS_GRAPH_IP=$(docker inspect -f '{{.NetworkSettings.Networks.bridge.IPAddress}}' aixcc-analysis-graph)
        export ANALYSIS_GRAPH_BOLT_URL=${ANALYSIS_GRAPH_BOLT_URL:-bolt://neo4j:helloworldpdt@${ANALYSIS_GRAPH_IP}:7687}
    popd
    pushd permanence
        docker compose down -v || true
        docker compose up --build -d
        export PERMANENCE_SERVER_PORT=31337
        export PERMANENCE_SERVER_IP=$(docker inspect -f '{{.NetworkSettings.Networks.bridge.IPAddress}}' aixcc-permanence-server)
        export PERMANENCE_SERVER_URL=${PERMANENCE_SERVER_URL:-http://${PERMANENCE_SERVER_IP}:${PERMANENCE_SERVER_PORT}}
        export PERMANENCE_SERVER_GLOBAL_URL=${PERMANENCE_SERVER_GLOBAL_URL:-http://beatty.unfiltered.seclab.cs.ucsb.edu:${PERMANENCE_SERVER_PORT}}
    popd

    pushd codeql_server
        docker compose down -v || true
        docker compose up --build -d
        CODEQL_SERVER_IP=$(docker inspect -f '{{.NetworkSettings.Networks.bridge.IPAddress}}' aixcc-codeql-server)
        export CODEQL_SERVER_URL=${CODEQL_SERVER_UL:-http://${CODEQL_SERVER_IP}:4000}

    popd

    pushd telemetry_db
        export DOCKER_GID=$(cut -d: -f3 < <(getent group docker))
        export INFLUXDB_ORG="artiphishell"
        export INFLUXDB_BUCKET="artiphishell"
        export INFLUXDB_TOKEN="shellphish-influxdb-token"
        docker compose down -v || true
        docker compose up --build -d influxdb telegraf otel-collector 
        INFLUXDB_IP=$(docker inspect -f '{{.NetworkSettings.Networks.bridge.IPAddress}}' telemetry_db)
        # OPENSEARCH_IP=$(docker inspect -f '{{.NetworkSettings.Networks.bridge.IPAddress}}' opensearch)
        OTEL_COLLECTOR_IP=$(docker inspect -f '{{.NetworkSettings.Networks.bridge.IPAddress}}' otel-collector)
        # echo "SIGNOZ BASIC AUTH: ${SIGNOZ_BASIC_AUTH}"
        export INFLUXDB_URL=${TELEMETRY_DB_URL:-http://${INFLUXDB_IP}:8086}
        # export OPENSEARCH_URL=${OPENSEARCH_URL:-http://${OPENSEARCH_IP}:9200}
        export OTEL_EXPORTER_OTLP_ENDPOINT=${OTEL_EXPORTER_OTLP_ENDPOINT:-http://${OTEL_COLLECTOR_IP}:4317}
        sleep 10
    popd

    pushd lang-server
      docker compose down || true
      docker compose build
      docker compose up --build -d
      export LANG_SERVER_IP=$(docker inspect -f '{{.NetworkSettings.Networks.bridge.IPAddress}}' aixcc-lang-server)
      export LANG_SERVER_URL=${LANG_SERVER_URL:-http://${LANG_SERVER_IP}:5000}
      sleep 5 # Language server also needs some time to come up
    popd


    pushd functionresolver_server
      docker compose down || true
      docker compose up --build -d
      export FUNC_RESOLVER_IP=$(docker inspect -f '{{.NetworkSettings.Networks.bridge.IPAddress}}' aixcc-functionresolver-server)
      export FUNC_RESOLVER_URL=${FUNC_RESOLVER_URL:-http://${FUNC_RESOLVER_IP}:4033}
      sleep 5
    popd

popd

# if the ARVO_START_LLM environment variable exists and is set to true, start the litellm service
if [ "${ARVO_START_LLM:-false}" = "true" ]; then
  pushd $ARTIPHISHELL_ROOT/infra/litellm
      docker compose down -v || true
      docker compose up --build -d
      LITELLM_IP=$(docker inspect -f '{{.NetworkSettings.Networks.bridge.IPAddress}}' aixcc-litellm)
      export LITELLM_HOSTNAME=${LITELLM_HOSTNAME:-http://${LITELLM_IP}:4001}
      export AIXCC_LITELLM_HOSTNAME=${LITELLM_HOSTNAME}
  popd
fi

echo "export ANALYSIS_GRAPH_BOLT_URL='$ANALYSIS_GRAPH_BOLT_URL'"
echo "export CODEQL_SERVER_URL='$CODEQL_SERVER_URL'"
echo "export FUNC_RESOLVER_URL='$FUNC_RESOLVER_URL'"