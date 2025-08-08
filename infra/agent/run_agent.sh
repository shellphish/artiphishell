#!/bin/bash

set -ex

# Ensure upload directory exists and start nginx (serving /tmp/pdt-uploads on port 8040)
mkdir -p /tmp/pdt-uploads
chmod 777 /tmp/pdt-uploads

# Launch nginx in background with auto-restart capability
(
    while true; do
        echo "Starting nginx..."
        nginx -g "daemon off;" | tee -a /pdt/nginx.log
        sleep 5
    done
) &

export LITELLM_KEY='sk-artiphishell-da-best!!!'

if [ -z "$AIXCC_LITELLM_HOSTNAME" ]; then
    echo "AIXCC_LITELLM_HOSTNAME was not set! Defaulting to http://litellm:4000/"
    export AIXCC_LITELLM_HOSTNAME='http://litellm:4000/'
fi
if [ "$AIXCC_LITELLM_HOSTNAME" = "http://litellm:4000/" ]; then
    export IN_CLUSTER_LITELLM=true
fi

export RETRIEVAL_API=http://example.com
export EMBEDDING_API=http://example.com
export DOCKER_HOST=tcp://docker-builder:2375

export CODEQL_SERVER_URL=http://codeql-TASKNUM:${CODEQL_1_SERVICE_PORT:-4000}

export NUM_CONCURRENT_TASKS=${NUM_CONCURRENT_TASKS:-8}

# TODO(finaldeploy) Make sure this is set to the correct number of task pools
export NUM_TASK_POOLS=$NUM_CONCURRENT_TASKS

# TODO(finaldeploy) Update this to a larger number like 29/64Gi/ LIMITS MUST BE LARGER
EXTRA_GLOBAL_ENVS=" \
  --global-script-env INITIAL_BUILD_CPU=29 \
  --global-script-env INITIAL_BUILD_MEM=64Gi \
  --global-script-env INITIAL_BUILD_MAX_CPU=40 \
  --global-script-env INITIAL_BUILD_MAX_MEM=80Gi \
"

echo "=== ARTIPHISHELL GLOBAL ENV ==="
env | grep ^ARTIPHISHELL_GLOBAL_ENV_ || true

echo
echo

EXTRA_PDT_CONFIG=""

if [ ! -z "$ARTIPHISHELL_GLOBAL_ENV_EXTRA_PDT_CONFIG" ]; then
    EXTRA_PDT_CONFIG="$EXTRA_PDT_CONFIG $ARTIPHISHELL_GLOBAL_ENV_EXTRA_PDT_CONFIG"
    unset ARTIPHISHELL_GLOBAL_ENV_EXTRA_PDT_CONFIG
fi

# Add all ARTIPHISHELL_GLOBAL_ENV_ variables to EXTRA_GLOBAL_ENVS
for var in $(env | grep ^ARTIPHISHELL_GLOBAL_ENV_ | cut -d= -f1); do
    EXTRA_GLOBAL_ENVS="$EXTRA_GLOBAL_ENVS --global-script-env $var=${!var}"
done

if [ "$ARTIPHISHELL_GLOBAL_ENV_INJECT_SEEDS" = "true" ]; then
    if [ ! -z "$AZURE_STORAGE_ACCOUNT_NAME" ] && [ "$AZURE_STORAGE_ACCOUNT_NAME" != "artiphishellci" ]; then
        echo "⚠️ REFUSING TO INJECT SEEDS INTO NON-CI ENVIRONMENTS"
        unset ARTIPHISHELL_GLOBAL_ENV_INJECT_SEEDS
    fi
fi

PROFILER=""

if [ -z "$CRS_TASK_NUM" ]; then
    echo "⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️ Traceback: CRS_TASK_NUM was not set! Defaulting to 1. This is really really really bad!!!"
    export CRS_TASK_NUM=1
fi

export ARTIPHISHELL_GLOBAL_ENV_CRS_TASK_NUM=$CRS_TASK_NUM


# TOOD Verify that the this hostname matches the given CRS_TASK_NUM


echo "Using image registry for new images: $ACR_SERVER"

export TEMP=/pdt/
mkdir -p $TEMP

PIPELINE_ID=$(cat /app/.pipeline-id)

# We found that there seems to be a race with PVC where sometimes the file may not be present right away and this has caused us to accidently relock when the pod restarts or redeploys

touch /pdt/.hello

sleep 60
sync

LOCKFILE_NAME=pipeline.lock
LOCKFILE_BACKUP=/pdt/pipeline.lock.$PIPELINE_ID.backup
LOCKFILE_BACKUP_2=/shared/pipeline-${CRS_TASK_NUM}.lock.$PIPELINE_ID.backup

for i in {1..10}; do
  if [ -f "$LOCKFILE_BACKUP" ]; then
    echo "found lockfile backup on attempt $i"
    break
  fi
  echo "waiting for filesystem to stabilize, attempt $i..."
  sync  # force filesystem sync
  sleep 2
done

export PDT_AGENT_URL=http://pydatatask-agent-${CRS_TASK_NUM}:8080

if [ -f $LOCKFILE_BACKUP ]; then
    mv $LOCKFILE_BACKUP $LOCKFILE_NAME
#elif [ -f $LOCKFILE_BACKUP_2 ]; then
#    mv $LOCKFILE_BACKUP_2 $LOCKFILE_NAME
else
    pdl \
        --no-lockstep \
        --name "artiphishell-${CRS_TASK_NUM}" \
        --exec-local-or-kube namespace=default \
        --image-prefix "$CRS_IMAGE_REGISTRY/" \
        --agent-host "pydatatask-agent-$CRS_TASK_NUM" \
        --agent-port 8080 \
        --no-launch-agent
    cp $LOCKFILE_NAME $LOCKFILE_BACKUP
    TIMESTAMP=$(date +%s)
    cp $LOCKFILE_NAME $LOCKFILE_BACKUP.$TIMESTAMP
    cp $LOCKFILE_NAME $LOCKFILE_BACKUP_2
    cp $LOCKFILE_NAME $LOCKFILE_BACKUP_2.$TIMESTAMP
fi

mkdir -p /pdt/agent-state/
mkdir -p /pdt/agent-state/nginx_cache
chmod 777 /pdt/agent-state/nginx_cache

# TODO(finaldeploy) Set these based on the size of the node
export PD_INJECT_CONCURRENCY_LIMIT=16
export PD_CAT_CONCURRENCY_LIMIT=16


(
    while true; do
        echo "Starting agent-http"
        pd agent-http \
            --host '0.0.0.0' \
             --override-port 8080 \
             --flush-seconds 200 \
             --state-dir /pdt/agent-state/ \
             --nginx-url http://nginx-pydatatask-agent-${CRS_TASK_NUM}:8080 \
             >> /pdt/agent-http.log 2>&1 || true
        echo "😵‍💫 Agent-http exited unexpectedly"
        tail -n 100 /pdt/agent-http.log
        sleep .5
    done
) &



# TODO XXX set the default values for the envs
API_COMPONENTS_USE_DUMMY_DATA=${API_COMPONENTS_USE_DUMMY_DATA:-1}
OSS_FUZZ_CACHE_TARGET_BUILDS=${OSS_FUZZ_CACHE_TARGET_BUILDS:-0}

if [ -z "$CACHE_REGISTRY" ]; then
    CACHE_REGISTRY=$ACR_SERVER
    CACHE_REGISTRY_USERNAME=$ACR_USERNAME
    CACHE_REGISTRY_PASSWORD=$ACR_PASSWORD
fi

export ANALYSIS_GRAPH_BOLT_URL="bolt://neo4j:$AGENT_SECRET@analysisgraph-TASKNUM:${ANALYSISGRAPH_1_SERVICE_PORT:-7687}"
export PERMANENCE_SERVER_URL="http://permanence:${PERMANENCE_SERVICE_PORT:-31337}"

if [ "$API_COMPONENTS_USE_DUMMY_DATA" = "1" ]; then
    export PERMANENCE_SERVER_GLOBAL_URL="http://beatty.unfiltered.seclab.cs.ucsb.edu:31337"
else
    export PERMANENCE_SERVER_GLOBAL_URL=""
fi

export FUNC_RESOLVER_URL="http://functionresolver-TASKNUM:${FUNCTIONRESOLVER_1_SERVICE_PORT:-4033}"

export INFLUXDB_URL="http://telemetrydb:${TELEMETRYDB_SERVICE_PORT:-8086}"
export INFLUXDB_TOKEN="shellphish-influxdb-token"
export INFLUXDB_BUCKET="artiphishell"
export INFLUXDB_ORG="artiphishell"

(
    while true; do
        ag-install-all-labels
        sleep 30m
    done &
)

(
    while true; do
        python3 /app/infra/agent/scripts/update_project_status.py 2>&1 | tee -a /pdt/update_project_status.log
        sleep 10
    done
) &
(
    while true; do
        python3 /app/infra/agent/scripts/monitor_nodes.py 2>&1 | tee -a /pdt/monitor_nodes.log
        sleep 10
    done
) &
(
    while true; do
        python3 /app/infra/agent/scripts/monitor_by_project.py 2>&1 | tee -a /pdt/monitor_by_project.log
        sleep 10
    done
) &
(
    while true; do
        python3 /app/infra/agent/scripts/prune_builds.py 2>&1 | tee -a /pdt/prune_nginx_cache.log
        sleep 10
    done
) &
(/app/infra/agent/scripts/track_pod_ips.sh 2>&1 | tee -a /pdt/track_pod_ips.log ) &

if [ "$ARTIPHISHELL_GLOBAL_ENV_PROFILE_PDT" = "true" ]; then
    mkdir -p /pdt/profiling_data
    pip install py-spy || true
fi

export DISALLOW_SINGLE_NODE_MODE=1

if [ "$ARTIPHISHELL_GLOBAL_ENV_INJECT_SEEDS" = "true" ]; then
    EXTRA_PDT_CONFIG="$EXTRA_PDT_CONFIG -T grammar_guy_fuzz -T grammar_agent_explore -T grammar_composer_run -T aflpp_fuzz -T aflpp_fuzz_main_replicant -T quick_seed -T quick_seed_delta -T jazzer_fuzz -T jazzer_fuzz_shellphish -T jazzer_fuzz_shellphish_codeql -T jazzer_fuzz_same_node_sync -T discovery_guy_from_ranking_delta -T discovery_guy_from_ranking_full -T corpus_kickstart -T aijon_fuzz -T aflrun_fuzz -T aijon_build -T aflpp_build_cmplog -T griller_fuzz -T coverage_trace"
fi

set +e
while true; do

if [ -f "/pdt/extra_envs.txt" ]; then
    # Load env vars 
    source /pdt/extra_envs.txt
fi

if [ "$ARTIPHISHELL_GLOBAL_ENV_PROFILE_PDT" = "true" ]; then
    mkdir -p /pdt/profiling_data
    if command -v py-spy &> /dev/null; then
        TIME_SEC=$(date +%s)
        PROFILER="py-spy record --format speedscope -o /pdt/profiling_data/agent-${CRS_TASK_NUM}-${TIME_SEC}.speedscope.json -- "
    else
        PROFILER=""
        echo "py-spy not installed, skipping profiling"
    fi
else
    PROFILER=""
fi

FILE_EXTRA_CONFIG=""
if [ -f "/pdt/extra_config.txt" ]; then
    FILE_EXTRA_CONFIG="$(cat /pdt/extra_config.txt)"
fi

$PROFILER python3 -m pydatatask.cli.main \
    $EXTRA_PDT_CONFIG \
    --global-template-env "crs_image_prefix=$ACR_SERVER/" \
    --global-script-env "IN_K8S=1" \
    --global-script-env "GITHUB_CREDS_PATH=/shared/secret/github" \
    --global-script-env "DOCKER_HOST=$DOCKER_HOST" \
    --global-script-env "DOCKER_IMAGE_PREFIX=$ACR_SERVER/" \
    --global-script-env "DOCKER_REGISTRY=$ACR_SERVER" \
    --global-script-env "DOCKER_LOGIN_SERVER=$ACR_SERVER" \
    --global-script-env "DOCKER_LOGIN_USERNAME=$ACR_USERNAME" \
    --global-script-env "DOCKER_LOGIN_PASSWORD=$ACR_PASSWORD" \
    --global-script-env "DOCKER_LOGIN_SERVER2=$CACHE_REGISTRY" \
    --global-script-env "DOCKER_LOGIN_USERNAME2=$CACHE_REGISTRY_USERNAME" \
    --global-script-env "DOCKER_LOGIN_PASSWORD2=$CACHE_REGISTRY_PASSWORD" \
    --global-script-env "COMPETITION_SERVER_URL=$COMPETITION_SERVER_URL" \
    --global-script-env "ARTIPHISHELL_CCACHE_DISABLE=0" \
    --global-script-env "COMPETITION_SERVER_API_ID=$COMPETITION_SERVER_API_ID" \
    --global-script-env "COMPETITION_SERVER_API_KEY=$COMPETITION_SERVER_API_KEY" \
    --global-script-env "API_COMPONENTS_USE_DUMMY_DATA=$API_COMPONENTS_USE_DUMMY_DATA" \
    --global-script-env "OSS_FUZZ_CACHE_TARGET_BUILDS=$OSS_FUZZ_CACHE_TARGET_BUILDS" \
    --global-script-env "OSS_FUZZ_CACHE_PREFIX=$CACHE_REGISTRY/" \
    --global-script-env "USE_LLM_API=1" \
    --global-script-env "LITELLM_KEY=$LITELLM_KEY" \
    --global-script-env "AIXCC_LITELLM_HOSTNAME=$AIXCC_LITELLM_HOSTNAME" \
    --global-script-env "RETRIEVAL_API=$RETRIEVAL_API" \
    --global-script-env "EMBEDDING_API=$EMBEDDING_API" \
    --global-script-env "ANALYSIS_GRAPH_BOLT_URL=$ANALYSIS_GRAPH_BOLT_URL" \
    --global-script-env "OTEL_EXPORTER_OTLP_ENDPOINT=$OTEL_EXPORTER_OTLP_ENDPOINT" \
    --global-script-env "INFLUXDB_URL=$INFLUXDB_URL" \
    --global-script-env "INFLUXDB_TOKEN=$INFLUXDB_TOKEN" \
    --global-script-env "INFLUXDB_BUCKET=$INFLUXDB_BUCKET" \
    --global-script-env "INFLUXDB_ORG=$INFLUXDB_ORG" \
    --global-script-env "CODEQL_SERVER_URL=$CODEQL_SERVER_URL" \
    --global-script-env "FUNC_RESOLVER_URL=$FUNC_RESOLVER_URL" \
    --global-script-env "PERMANENCE_SERVER_URL=$PERMANENCE_SERVER_URL" \
    $EXTRA_GLOBAL_ENVS \
    $FILE_EXTRA_CONFIG \
    --verbose --debug-trace \
    run --forever 2>&1 | tee -a /pdt/agent.log || true

sleep 10

done
