#!/bin/bash

set -ex

# Install dependencies

sudo apt-get update -y && sudo apt-get install -y git unzip tar graphviz xdg-utils
python -m pip install --upgrade pip

export CODEQL_SERVER_URL='http://localhost:4000'

pushd ../../libs/libcodeql
    pip install -e .
popd

# Set up codeql client
pushd ../../services/codeql_server
    docker compose up -d --build --force-recreate --no-deps --remove-orphans
    # Add a restart policy update to ensure it doesn't restart
    docker update --restart=no $(docker compose ps -q)
    sleep 10
popd

CODEQL_SERVER_URL='http://localhost:4000'  codeql-upload-db  --cp_name mock-cp-java --project_id 1 \
 --language java --db_file ./tests/targets/mock-cp-java/codeql-database.tar.gz

export PROJECT_ID="1"
export PROJECT_NAME="mock-cp-java"
TEMP_DIR=$(mktemp -d -t quickseed-XXXXX)
export QUICKSEED_CODEQL_REPORT="${TEMP_DIR}/quickseed_codeql_report.yaml"

export ON_CI=true
export LOG_LEVEL=info

python3 ./quickseed_query/run_quickseed_query.py --project-name "${PROJECT_NAME}" --project-id "${PROJECT_ID}" --output-path "${QUICKSEED_CODEQL_REPORT}"
QUICKSEED_QUERY_EXIT_CODE=$?

docker kill aixcc-codeql-server || true
docker rm aixcc-codeql-server || true

sudo chown -R $(id -u):$(id -g) ../../services/codeql_server # Reset permissions

exit $QUICKSEED_QUERY_EXIT_CODE