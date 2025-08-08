#!/bin/bash

cd $(dirname $0)

set -ex

(
    while true; do
        python3 /app/infra/api/scripts/llm_budget_manager.py 2>&1 | tee -a /shared/llm_budget_manager.log
        sleep 10
    done
) &

# The flask app variable is located in crs_api.crs_api_endpoints

export INFLUXDB_URL="http://${TELEMETRYDB_SERVICE_HOST:-telemetrydb}:${TELEMETRYDB_SERVICE_PORT:-8086}"
export INFLUXDB_TOKEN="shellphish-influxdb-token"
export INFLUXDB_BUCKET="artiphishell"
export INFLUXDB_ORG="artiphishell"

echo "Starting API..."
echo "INFLUXDB_URL: $INFLUXDB_URL"
echo "INFLUXDB_TOKEN: $INFLUXDB_TOKEN"
echo "INFLUXDB_BUCKET: $INFLUXDB_BUCKET"
echo "INFLUXDB_ORG: $INFLUXDB_ORG"
gunicorn -w 4 -b 0.0.0.0:80 --access-logfile - --capture-output --log-level debug --timeout 300 crs_api.crs_api_endpoints:app