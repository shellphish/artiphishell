#!/usr/bin/env bash

# Default values for environment variables
export DISABLE_VDS_TIMEOUT=${DISABLE_VDS_TIMEOUT:-0}
export DISABLE_GP_TIMEOUT=${DISABLE_GP_TIMEOUT:-0}
export ROUND_TIME_SECONDS=${ROUND_TIME_SECONDS:-14400}
export INITIAL_SEEDS_DIR="/shared/injected-seeds/"

# Whether to use dummy data for the API components
export API_COMPONENTS_USE_DUMMY_DATA=${API_COMPONENTS_USE_DUMMY_DATA:-0}

# LiteLLM API
export LITELLM_KEY=${LITELLM_KEY:-'sk-artiphishell-da-best!!!'}
export AIXCC_LITELLM_HOSTNAME=${AIXCC_LITELLM_HOSTNAME:-http://wiseau.seclab.cs.ucsb.edu:666/}
export USE_LLM_API=${USE_LLM_API:-0} # Whether to use the LiteLLM API or not for agentlib

# Service API endpoints
export RETRIEVAL_API=http://beatty.unfiltered.seclab.cs.ucsb.edu:48751
export EMBEDDING_API=http://beatty.unfiltered.seclab.cs.ucsb.edu:49152
export FUNC_RESOLVER_URL=${FUNC_RESOLVER_URL}
export ANALYSIS_GRAPH_BOLT_URL=${ANALYSIS_GRAPH_BOLT_URL}
export PERMANENCE_SERVER_URL=${PERMANENCE_SERVER_URL}
export PERMANENCE_SERVER_GLOBAL_URL=${PERMANENCE_SERVER_GLOBAL_URL}
export CODEQL_SERVER_URL=${CODEQL_SERVER_URL}
export LANG_SERVER_URL=${LANG_SERVER_URL}

if [ -z "${BUDGET_STRATEGY:-}" ]; then
    if [ "$API_COMPONENTS_USE_DUMMY_DATA" == "1" ]; then
        export BUDGET_STRATEGY="cheapo"
    else
        export BUDGET_STRATEGY="balanced"
    fi
fi


# Competition server API endpoints
export COMPETITION_SERVER_API_ID=${COMPETITION_SERVER_API_ID:-"11111111-1111-1111-1111-111111111111"}
export COMPETITION_SERVER_API_KEY=${COMPETITION_SERVER_API_KEY:-"secret"}
if [ -z "${COMPETITION_SERVER_URL:-}" ]; then
    export API_COMPONENTS_USE_DUMMY_DATA=1
    export COMPETITION_SERVER_URL=${COMPETITION_SERVER_URL:-http://localhost:1323}
else
    export COMPETITION_SERVER_URL=${COMPETITION_SERVER_URL:-http://localhost:1323}
fi

# Our telemetry endpoints
export INFLUXDB_URL=${INFLUXDB_URL:-http://${INFLUXDB_IP}:8086}
export INFLUXDB_TOKEN=${INFLUXDB_TOKEN:-shellphish-influxdb-token}
export INFLUXDB_BUCKET=${INFLUXDB_BUCKET:-artiphishell}
export INFLUXDB_ORG=${INFLUXDB_ORG:-artiphishell}

export OTEL_EXPORTER_OTLP_ENDPOINT=${OTEL_EXPORTER_OTLP_ENDPOINT}

# Function to generate global script env arguments
generate_env_args() {
    # Define the list of environment variables to include
    env_vars=(
        "AIXCC_LITELLM_HOSTNAME"
        "INFLUXDB_URL"
        "INFLUXDB_TOKEN"
        "INFLUXDB_BUCKET"
        "INFLUXDB_ORG"
        "OTEL_EXPORTER_OTLP_ENDPOINT"
        "DISABLE_GP_TIMEOUT"
        "DISABLE_VDS_TIMEOUT"
        "ROUND_TIME_SECONDS"
        "RETRIEVAL_API"
        "EMBEDDING_API"

        # Service API endpoints
        "FUNC_RESOLVER_URL"
        "LANG_SERVER_URL"
        "PERMANENCE_SERVER_URL"
        "PERMANENCE_SERVER_GLOBAL_URL"
        "CODEQL_SERVER_URL"
        "ANALYSIS_GRAPH_BOLT_URL"

        "LITELLM_KEY"
        "API_COMPONENTS_USE_DUMMY_DATA"
        "USE_LLM_API"
        "COMPETITION_SERVER_API_ID"
        "COMPETITION_SERVER_API_KEY"
        "COMPETITION_SERVER_URL"
        "INITIAL_SEEDS_DIR"
        "BUDGET_STRATEGY"
    )

    # Build the command string
    cmd=""

    # Add environment variables from the list
    for var in "${env_vars[@]}"; do
        value="${!var}"
        cmd+="--global-script-env \"$var=$value\" "
    done

    echo "$cmd"
}
