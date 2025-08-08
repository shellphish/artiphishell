#!/bin/bash

set -ex

# Install dependencies

sudo apt-get update -y && sudo apt-get install -y git unzip tar graphviz xdg-utils
python -m pip install --upgrade pip

export CODEQL_SERVER_URL='http://localhost:4000'
export ANALYSIS_GRAPH_BOLT_URL='bolt://neo4j:helloworldpdt@localhost:7687'
export FUNC_RESOLVER_URL='http://localhost:4033'

pushd ../../libs/libcodeql
    pip install -e .
popd

pushd ../../libs/analysis-graph
    pip install -e .
popd

pushd ../../libs/crs-utils
    pip install -e .
popd

# Set up codeql client
pushd ../../services/codeql_server
    docker compose up -d --build --force-recreate --no-deps --remove-orphans
    # Add a restart policy update to ensure it doesn't restart
    docker update --restart=no $(docker compose ps -q)
popd

pushd ../../services/analysis_graph
    docker compose up -d --force-recreate --no-deps --remove-orphans
    # Add a restart policy update to ensure it doesn't restart
    docker update --restart=no $(docker compose ps -q)
popd

pushd ../../services/functionresolver_server
    docker compose up -d --force-recreate --no-deps --remove-orphans
    # Add a restart policy update to ensure it doesn't restart
    docker update --restart=no $(docker compose ps -q)
popd

sleep 10

# NGINX

CODEQL_SERVER_URL='http://localhost:4000'  codeql-upload-db  --cp_name nginx --project_id "4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865" \
 --language cpp --db_file ./tests/targets/nginx/sss-codeql-database.zip

mkdir -p /tmp/func_resolver || true
cp ./tests/targets/nginx/func_index.tar /tmp/func_resolver/data.tar


export CP_NAME="nginx"
export PROJ_ID="4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865"
export LANG="c"

python3 init_func_resolver.py
docker logs aixcc-functionresolver-server || true
python3 ./callgraph/analysis_query.py

docker kill aixcc-codeql-server || true
docker kill aixcc-functionresolver-server || true
docker kill aixcc-analysis-graph || true
docker rm aixcc-codeql-server || true
docker rm aixcc-functionresolver-server || true
docker rm aixcc-analysis-graph || true

# Restart services for next target
pushd ../../services/codeql_server
    docker compose up -d --force-recreate --no-deps --remove-orphans
    # Add a restart policy update to ensure it doesn't restart
    docker update --restart=no $(docker compose ps -q)
popd

pushd ../../services/analysis_graph
    docker compose up -d --force-recreate --no-deps --remove-orphans
    # Add a restart policy update to ensure it doesn't restart
    docker update --restart=no $(docker compose ps -q)
popd

pushd ../../services/functionresolver_server
    docker compose up -d --force-recreate --no-deps --remove-orphans
    # Add a restart policy update to ensure it doesn't restart
    docker update --restart=no $(docker compose ps -q)
popd

# TIKA
CODEQL_SERVER_URL='http://localhost:4000'  codeql-upload-db  --cp_name tika --project_id "c0e49f3027e944e5a35c65e6c8079a8f" \
 --language java --db_file ./tests/targets/tika/sss-codeql-database.zip

mkdir -p /tmp/func_resolver || true
cp ./tests/targets/tika/func_index.tar /tmp/func_resolver/data.tar


export CP_NAME="tika"
export PROJ_ID="c0e49f3027e944e5a35c65e6c8079a8f"
export LANG="jvm"

python3 init_func_resolver.py
python3 ./callgraph/analysis_query.py

docker kill aixcc-codeql-server || true
docker kill aixcc-functionresolver-server || true
docker kill aixcc-analysis-graph || true
docker rm aixcc-codeql-server || true
docker rm aixcc-functionresolver-server || true
docker rm aixcc-analysis-graph || true

rm -rf /tmp/func_resolver

sudo chown -R $(id -u):$(id -g) ../../services/codeql_server # Reset permissions
