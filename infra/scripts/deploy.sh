#!/bin/bash

set -xe

SCRIPT_DIR=$(realpath $(dirname $0))

cd $SCRIPT_DIR/..
INFRADIR=$(realpath $(dirname $0)/..)

set +x
. tmp/.env
set -x

export USE_CLUSTER_LITELLM=${USE_CLUSTER_LITELLM:-true}

export INCLUDE_CI_PODS=${INCLUDE_CI_PODS:-false}
export INCLUDE_NODE_VIZ=${INCLUDE_NODE_VIZ:-true}
export ENABLE_PUBLIC_IP=${ENABLE_PUBLIC_IP:-true}
if [ "$NO_PUBLIC_IP" == "true" ]; then
  export ENABLE_PUBLIC_IP="false"
fi

if [ "$ARTIPHISHELL_GLOBAL_ENV_INJECT_SEEDS" == "true" ]; then
  # If the existing `FUZZER_VM_SIZE` has 64 in it we want a 32 core VM
  # otherwise we want a 16 core VM
  if [[ "$FUZZER_VM_SIZE" =~ 64 ]]; then
    export FUZZER_VM_SIZE=standard_D32s_v3
  else
    export FUZZER_VM_SIZE=standard_D16s_v3
  fi
  export MAX_FUZZER_NODES=2
fi

pushd tf

export WORKER_TOKEN=${WORKER_TOKEN:-null}

if [ "$ARTIPHISHELL_GLOBAL_ENV_INJECT_SEEDS" == "true" ]; then
  # MAKE SURE WE ARE RUNNING IN CI
  if [ "$INCLUDE_CI_PODS" == "false" ]; then
    echo "⚠️  Refusing to set INJECT_SEEDS to true when we are not in a CI deployment"
    unset ARTIPHISHELL_GLOBAL_ENV_INJECT_SEEDS
  fi
fi


export NUM_CONCURRENT_TASKS=${NUM_CONCURRENT_TASKS:-1}

export CURRENT_WORKSPACE=$(terraform workspace show)

if [ -z "$DEPLOYMENT_NAME" ]; then
  export DEPLOYMENT_NAME=$CURRENT_WORKSPACE
fi

if [ ! -z "$NUM_NODES" ] && [ -z "$NUM_USER_NODES" ]; then
  export NUM_USER_NODES=$NUM_NODES
else
  export NUM_USER_NODES=${NUM_USER_NODES:-1}
fi

export VM_DISK_SIZE=${VM_DISK_SIZE:-1024}

export MAX_USER_NODES=${MAX_USER_NODES:-4}

export NUM_FUZZER_NODES=${NUM_FUZZER_NODES:-0}
export MAX_FUZZER_NODES=${MAX_FUZZER_NODES:-3}
export MAX_FUZZER_NODES_LF=${MAX_FUZZER_NODES_LF:-1}

export NUM_PATCHER_NODES=${NUM_PATCHER_NODES:-0}
export MAX_PATCHER_NODES=${MAX_PATCHER_NODES:-3}

export MAX_SERVICE_NODES=${MAX_SERVICE_NODES:-8}

export MAX_COVERAGE_NODES=${MAX_COVERAGE_NODES:-5}

export ENABLE_GPU=${ENABLE_GPU:-true}

VER="v3"

if [ -z "$VM_SIZE" ]; then
  if [[ "$CURRENT_WORKSPACE" =~ ^ni ]]; then
    VM_SIZE="standard_D32s_v3"
    VER="v3"
  else
    VM_SIZE="standard_D32s_v3"
    VER="v3"
  fi
fi

export USER_VM_SIZE=${USER_VM_SIZE:-$VM_SIZE}
export FUZZER_VM_SIZE=${FUZZER_VM_SIZE:-standard_D32s_${VER}}
export FUZZER_VM_SIZE_LF=${FUZZER_VM_SIZE_LF:-$FUZZER_VM_SIZE}
export PATCHER_VM_SIZE=${PATCHER_VM_SIZE:-standard_D16s_${VER}}
export CRITICAL_VM_SIZE=${CRITICAL_VM_SIZE:-standard_D16s_${VER}}
export SERVICE_VM_SIZE=${SERVICE_VM_SIZE:-standard_D16s_v3}
export COVERAGE_VM_SIZE=${COVERAGE_VM_SIZE:-standard_D16s_v3}

$INFRADIR/scripts/print_run_config.sh || true

if [[ ! "$*" =~ "--skiptf" ]]; then
  if [ "$CURRENT_WORKSPACE" != "default" ]; then
    terraform init \
      -reconfigure \
      -backend-config="key=terraform.tfstate.$CURRENT_WORKSPACE"
  else
    terraform init
  fi

  TERRAFORM_ARGS="\
    -var=enable_public_ip=$ENABLE_PUBLIC_IP \
    -var=usr_node_count=$NUM_USER_NODES \
    -var=fuzzing_node_count=$NUM_FUZZER_NODES \
    -var=patching_node_count=$NUM_PATCHER_NODES \
    -var=usr_node_count_max=$MAX_USER_NODES \
    -var=fuzzing_node_count_max=$MAX_FUZZER_NODES \
    -var=fuzzing_node_count_max_lf=$MAX_FUZZER_NODES_LF \
    -var=patching_node_count_max=$MAX_PATCHER_NODES \
    -var=services_node_count_max=$MAX_SERVICE_NODES \
    -var=coverage_node_count_max=$MAX_COVERAGE_NODES \
    -var=vm_size=$USER_VM_SIZE \
    -var=fuzzing_vm_size=$FUZZER_VM_SIZE \
    -var=fuzzing_vm_size_lf=$FUZZER_VM_SIZE_LF \
    -var=critical_vm_size=$CRITICAL_VM_SIZE \
    -var=patching_vm_size=$PATCHER_VM_SIZE \
    -var=coverage_vm_size=$COVERAGE_VM_SIZE \
    -var=task_pool_count=$NUM_CONCURRENT_TASKS \
    -var=services_vm_size=$SERVICE_VM_SIZE \
    -var=vm_disk_size=$VM_DISK_SIZE \
    -var=enable_gpu_node_pool=$ENABLE_GPU \
  "

  if [[ "$*" =~ "--only-registry" ]]; then
    TERRAFORM_ARGS="\
      $TERRAFORM_ARGS \
      -target=random_pet.rg_name \
      -target=azurerm_resource_group.rg \
      -target=random_string.acr_suffix \
      -target=azurerm_container_registry.acr
    "
  fi

  set +e
  terraform plan -detailed-exitcode $TERRAFORM_ARGS
  terraform_exit_status=$?
  set -e

  if [ $terraform_exit_status -eq 0 ]; then
    terraform_no_changes=true
  else
    terraform_no_changes=false

    while true; do
      terraform apply -auto-approve $TERRAFORM_ARGS 2>&1 | tee /tmp/terraform-apply.log
      if grep -q "Apply complete" /tmp/terraform-apply.log; then
        break
      fi

      if grep -q "Standard_NC40ads_H100_v5' is not supported for subscription" /tmp/terraform-apply.log; then
        echo "Standard_NC40ads_H100_v5' is not supported for subscription, disabling GPU node pool"
        # replace the -var=enable_gpu_node_pool=true part of the TERRAFORM_ARGS with -var=enable_gpu_node_pool=false
        TERRAFORM_ARGS=$(echo $TERRAFORM_ARGS | sed 's/-var=enable_gpu_node_pool=true/-var=enable_gpu_node_pool=false/')
        sleep 10
        continue
      fi

      echo "Terraform apply failed, exiting..."
      exit 1
    done

  fi


  DNS_NAME=$(terraform output -raw dns_name)
  # Get just the first part up to the first dot
  DNS_NAME=$(echo $DNS_NAME | cut -d. -f1)
  VIZ_DNS_NAME=viz.$DNS_NAME
  NODEVIZ_DNS_NAME=nodes.$DNS_NAME

  #API_IP=$($SCRIPT_DIR/get_cluster_ip.sh)
  #AGENT_IP=$($SCRIPT_DIR/get_agent_ip.sh)
  #NODEVIZ_IP=$($SCRIPT_DIR/get_nodeviz_ip.sh)
fi

if [[ "$*" =~ "--skiptf" ]] && [ -f ../tmp/.k8-env ]; then
  . ../tmp/.k8-env
else
  set +e
  LOGIN_SERVER=$(terraform output -raw acr_login_server)
  USERNAME=$(terraform output -raw acr_admin_username)
  PASSWORD=$(terraform output -raw acr_admin_password)
  RG=$(terraform output -raw resource_group_name)
  K8_NAME=$(terraform output -raw kubernetes_cluster_name 2>/dev/null)
  DNS_NAME=$(terraform output -raw dns_name)
  set -e
  # Cache the values
  cat <<EOF > ../tmp/.k8-env
LOGIN_SERVER=$LOGIN_SERVER
USERNAME=$USERNAME
PASSWORD=$PASSWORD
RG=$RG
K8_NAME=$K8_NAME
DNS_NAME=$DNS_NAME
EOF
fi

popd

sleep 10

if [[ ! "$*" =~ "--only-registry" ]]; then
  timeout 60 scripts/access_k8.sh
fi

if [[ ! "$*" =~ "--skipinstall" ]]; then

if [[ "$*" =~ "--restart" ]] || [[ "$*" =~ "--uninstall" ]]; then
  ($SCRIPT_DIR/stop_helm.sh || true) &
fi

fi

if [[ "$*" =~ "--skiptf" ]] || [[ "$*" =~ "--only-registry" ]]; then
  echo "Skipping az configuration"
elif [ "$terraform_no_changes" != "true" ]; then
  # Preload any static images into the registry
  echo "Preloading images into registry $LOGIN_SERVER"
  #(./scripts/cache_images.sh || true) &

  echo "Applying direct configuration to azure..."
  # AFAIK you can't apply these configs in the aks terraform module, so we do it here
  # This will define the autoscaler behavior that needs to be changed from the default
  (az aks update \
    -g $RG \
    -n $K8_NAME \
    --cluster-autoscaler-profile "daemonset-eviction-for-empty-nodes=true,expander=priority,skip-nodes-with-local-storage=true,scale-down-unneeded-time=5m,max-graceful-termination-sec=30,ignore-daemonsets-utilization=true" --no-wait || true
  ) &

  # This doesn't actually work... none of the logs show up in our log analytics workspace
  #(./scripts/setup_container_logging.sh || true) &


  CLIENT_ID=$(az aks show --query identity.principalId -g $RG -n $K8_NAME --output tsv)
  RG_SCOPE=$(az aks show --query id -g $RG -n $K8_NAME --output tsv)
  az role assignment create --assignee ${CLIENT_ID} --role "Network Contributor" --scope ${RG_SCOPE} || true

fi

set -x


pushd k8/charts/artiphishell

helm dependency update

set +x
if [ "$EXCLUDE_GITHUB_CREDENTIALS" == "true" ]; then
  GITHUB_TOKEN="null"
else
  GITHUB_TOKEN=$(cat $HOME/.git-credentials | head -n 1)
fi
set -x

#helm upgrade --install ingress-nginx ingress-nginx \
#  --repo https://kubernetes.github.io/ingress-nginx \
#  --namespace ingress-nginx --create-namespace

if [ -z "$CI_ACR_SERVER" ] || [ "$NO_EXTERNAL_REGISTRY" == "true" ]; then
  CACHE_REGISTRY_SERVER=$LOGIN_SERVER
  CACHE_REGISTRY_USERNAME=$USERNAME
  CACHE_REGISTRY_PASSWORD=$PASSWORD
else
  CACHE_REGISTRY_SERVER=$CI_ACR_SERVER
  CACHE_REGISTRY_USERNAME=$CI_ACR_USERNAME
  CACHE_REGISTRY_PASSWORD=$CI_ACR_PASSWORD
fi

if [ -z "$CI_ACR_SERVER" ] || [ "$NO_EXTERNAL_REGISTRY" == "true" ]; then
  CI_ACR_SERVER=$LOGIN_SERVER
  CI_ACR_USERNAME=$USERNAME
  CI_ACR_PASSWORD=$PASSWORD
fi


if [[ ! "$*" =~ "--skipinstall" ]] && [[ ! "$*" =~ "--uninstall" ]]; then

pushd $INFRADIR/k8
kubectl apply -f autoscale_priority.yaml
kubectl apply -f dns_log.yaml
popd

if [[ "$*" =~ "--restart" ]]; then
  wait
fi

export API_COMPONENTS_USE_DUMMY_DATA=${API_COMPONENTS_USE_DUMMY_DATA:-0}
export SHELLPHISH_IS_CI=${SHELLPHISH_IS_CI:-false}

if [ -z "$BUDGET_STRATEGY" ]; then
  if [ "$SHELLPHISH_IS_CI" == "true" ]; then
    export BUDGET_STRATEGY="cheapo"
  else
    export BUDGET_STRATEGY="balanced"
  fi
fi

if [ ! -z "$COMPETITION_API_KEY_ID" ]; then
  COMPETITION_SERVER_API_ID=$COMPETITION_API_KEY_ID
fi
if [ ! -z "$COMPETITION_API_KEY_TOKEN" ]; then
  COMPETITION_SERVER_API_KEY=$COMPETITION_API_KEY_TOKEN
fi
if [ ! -z "$COMPETITION_API_URL" ]; then
  COMPETITION_SERVER_URL=$COMPETITION_API_URL
fi
if [ ! -z "$CRS_KEY_ID" ]; then
  ARTIPHISHELL_API_USERNAME=$CRS_KEY_ID
fi
if [ ! -z "$CRS_KEY_TOKEN" ]; then
  ARTIPHISHELL_API_PASSWORD=$CRS_KEY_TOKEN
fi
if [ ! -z "$CRS_API_URL" ]; then
  ARTIPHISHELL_API_URL=$CRS_API_URL
elif [ ! -z "$CRS_API_HOSTNAME" ]; then
  ARTIPHISHELL_API_URL=http://$CRS_API_HOSTNAME
fi
if [ ! -z "$OTEL_EXPORTER_OTLP_ENDPOINT" ]; then
  # Check if OTEL_EXPORTER_OTLP_ENDPOINT already has a port
  if [[ "$OTEL_EXPORTER_OTLP_ENDPOINT" =~ :[0-9]+$ ]]; then
    export SIGNOZ_OTEL_EXPORTER_OTLP_ENDPOINT=${OTEL_EXPORTER_OTLP_ENDPOINT}
  else
    export SIGNOZ_OTEL_EXPORTER_OTLP_ENDPOINT=${OTEL_EXPORTER_OTLP_ENDPOINT}:443
  fi
  export OTEL_EXPORTER_OTLP_ENDPOINT="http://otel-collector:4317"
fi



export ARTIPHISHELL_API_USERNAME=${ARTIPHISHELL_API_USERNAME:-shellphish}
export ARTIPHISHELL_API_PASSWORD=${ARTIPHISHELL_API_PASSWORD:-!!!shellphish!!!}
export ARTIPHISHELL_API_URL=${ARTIPHISHELL_API_URL:-http://api:80}

export COMPETITION_SERVER_API_ID=${COMPETITION_SERVER_API_ID:-"11111111-1111-1111-1111-111111111111"}
export COMPETITION_SERVER_API_KEY=${COMPETITION_SERVER_API_KEY:-"secret"}
export COMPETITION_SERVER_URL=${COMPETITION_SERVER_URL:-http://aixcc-server-infra:1323}

export OTEL_EXPORTER_OTLP_ENDPOINT=${OTEL_EXPORTER_OTLP_ENDPOINT:-http://otel-collector:4317}
export SIGNOZ_BASIC_AUTH=$(echo -n "${COMPETITION_SERVER_API_ID}:${COMPETITION_SERVER_API_KEY}" | base64 -w0)
export SIGNOZ_OTEL_EXPORTER_OTLP_ENDPOINT=${SIGNOZ_OTEL_EXPORTER_OTLP_ENDPOINT:-"http://aixcc-server-infra:4317"}
export SIGNOZ_TLS_INSECURE=${SIGNOZ_TLS_INSECURE:-$(echo -n "$SIGNOZ_OTEL_EXPORTER_OTLP_ENDPOINT" | grep -q "^http://" && echo "true" || echo "false")}

env | grep ^ARTIPHISHELL_GLOBAL_ENV_ | tee /tmp/artiphishell_global.env

# This determines which registry the actual task images will be pulled from
# TODO make this more robust
if [ "$NO_EXTERNAL_REGISTRY" == "true" ]; then
  DEPLOYMENT_REGISTRY=$LOGIN_SERVER
else
  DEPLOYMENT_REGISTRY=$CI_ACR_SERVER
fi


function helm_upgrade() {
VERBOSITY=""
if [ "$VERBOSE" == "true" ]; then
  VERBOSITY="--debug"
fi

if [ ! -z "$LITELLM_SECRETS_PATH" ]; then
  echo "🔑 Using LITELLM_SECRETS_PATH: $LITELLM_SECRETS_PATH"
elif [ "$USE_CLUSTER_LITELLM" == "true" ]; then

# Here we will create the env file which should be loaded by the litellm deployment
set +x
cat <<EOF > $INFRADIR/tmp/litellm.env
OPENAI_API_KEY=$OPENAI_API_KEY
ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY
AZURE_API_KEY=$AZURE_API_KEY
AZURE_API_BASE=$AZURE_API_BASE
GEMINI_API_KEY=$GEMINI_API_KEY
AZURE_OPENAI_KEY=$AZURE_OPENAI_KEY
AZURE_OPENAI_ENDPOINT=$AZURE_OPENAI_ENDPOINT
GOOGLE_APPLICATION_CREDENTIALS=/etc/google/credentials.json
EOF
set -x
LITELLM_SECRETS_PATH=$INFRADIR/tmp/litellm.env
else
  if [ ! -z "$MUST_USE_CLUSTER_LITELLM" ]; then
    echo "LITELLM_SECRETS_PATH is not set, but MUST_USE_CLUSTER_LITELLM is set"
    exit 1;
  fi
  export USE_CLUSTER_LITELLM=true
fi


if [ ! -z "$GOOGLE_APPLICATION_CREDENTIALS_PATH" ]; then
  if [ -f "$GOOGLE_APPLICATION_CREDENTIALS_PATH" ]; then
    echo "🔑 Creating secret from Google credentials file: $GOOGLE_APPLICATION_CREDENTIALS_PATH"
    kubectl create secret generic google-credentials \
      --from-file=credentials.json="$GOOGLE_APPLICATION_CREDENTIALS_PATH" \
      --dry-run=client -o yaml | kubectl apply -f -
  else
    echo "Warning: GOOGLE_APPLICATION_CREDENTIALS_PATH is set but file does not exist: $GOOGLE_APPLICATION_CREDENTIALS_PATH"
  fi
fi
if [ ! -s /tmp/artiphishell_global.env ]; then
  echo "ARTIPHISHELL_GLOBAL_ENV_A=B" > /tmp/artiphishell_global.env
fi

if [ -s /tmp/artiphishell_global.env ]; then
  # Create a configmap from the env file, no secrets here
  kubectl create configmap artiphishell-global-env \
    --from-env-file=/tmp/artiphishell_global.env \
    --dry-run=client -o yaml | kubectl apply -f -
fi
  
# Create litellm secrets directly using kubectl if env file exists
if [ ! -z "$LITELLM_SECRETS_PATH" ] && [ -f "$LITELLM_SECRETS_PATH" ]; then
  # Create the secret directly from the env file
  kubectl create secret generic litellm-secrets \
    --from-env-file=$LITELLM_SECRETS_PATH \
    --dry-run=client -o yaml | kubectl apply -f -
else
  if [ ! -z "$MUST_USE_CLUSTER_LITELLM" ]; then
    echo "LITELLM_SECRETS_PATH is not set, but MUST_USE_CLUSTER_LITELLM is set"
    exit 1;
  fi
  export USE_CLUSTER_LITELLM=false
fi

if [ "$USE_CLUSTER_LITELLM" == "true" ]; then
  export AIXCC_LITELLM_HOSTNAME='http://litellm:4000/'
else
  if [ ! -z "$MUST_USE_CLUSTER_LITELLM" ]; then
    echo "Refusing to use non-cluster litellm when MUST_USE_CLUSTER_LITELLM is set"
    exit 1;
  fi
  export AIXCC_LITELLM_HOSTNAME='http://wiseau.seclab.cs.ucsb.edu:666/'
fi

export TARGET_STORAGE_CONTAINER=${TARGET_STORAGE_CONTAINER:-null}
export TARGET_STS_TOKEN=${TARGET_STS_TOKEN:-null}
export STORAGE_CONNECTION_STRING=${STORAGE_CONNECTION_STRING:-null}

# set pipefail so that the tee command will fail if the helm command fails
set -o pipefail
set -u  # Exit if any variable is unset or undefined
helm upgrade --install $VERBOSITY artiphishell . \
  --set "global.acr.server=$LOGIN_SERVER" \
  --set "global.acr.username=$USERNAME" \
  --set "global.acr.password=$PASSWORD" \
  --set "global.ci_acr.server=$CI_ACR_SERVER" \
  --set "global.ci_acr.username=$CI_ACR_USERNAME" \
  --set "global.ci_acr.password=$CI_ACR_PASSWORD" \
  --set "global.cache_registry.server=$CACHE_REGISTRY_SERVER" \
  --set "global.cache_registry.username=$CACHE_REGISTRY_USERNAME" \
  --set "global.cache_registry.password=$CACHE_REGISTRY_PASSWORD" \
  --set "global.agentSecret.value=$AGENT_SECRET" \
  --set "global.ci_worker_token.value=$WORKER_TOKEN" \
  --set "global.github.token=$GITHUB_TOKEN" \
  --set "global.is_ci=$SHELLPHISH_IS_CI" \
  --set "global.budget_strategy=$BUDGET_STRATEGY" \
  --set "global.aixcc_litellm_hostname.value=$AIXCC_LITELLM_HOSTNAME" \
  --set "global.artiphish_api_username.value=$ARTIPHISHELL_API_USERNAME" \
  --set "global.artiphish_api_password.value=$ARTIPHISHELL_API_PASSWORD" \
  --set "global.artiphish_api_url.value=$ARTIPHISHELL_API_URL" \
  --set "global.competition_server_api_id.value=$COMPETITION_SERVER_API_ID" \
  --set "global.competition_server_api_key.value=$COMPETITION_SERVER_API_KEY" \
  --set "global.competition_server_url.value=$COMPETITION_SERVER_URL" \
  --set "otel-collector.signoz_otel_exporter_otlp_endpoint.value=$SIGNOZ_OTEL_EXPORTER_OTLP_ENDPOINT" \
  --set "otel-collector.signoz_basic_auth.value=$SIGNOZ_BASIC_AUTH" \
  --set "otel-collector.signoz_tls_insecure.value=$SIGNOZ_TLS_INSECURE" \
  --set "global.deployment_registry.value=$DEPLOYMENT_REGISTRY" \
  --set "global.deployment_name.value=$DEPLOYMENT_NAME" \
  --set "global.api_dns_name.value=$DNS_NAME" \
  --set "global.otel_exporter_otlp_endpoint.value=$OTEL_EXPORTER_OTLP_ENDPOINT" \
  --set "global.include_ci_pods.value=$INCLUDE_CI_PODS" \
  --set "global.include_node_viz.value=$INCLUDE_NODE_VIZ" \
  --set "global.enable_public_ip.value=$ENABLE_PUBLIC_IP" \
  --set "global.max_fuzzer_nodes.value=$MAX_FUZZER_NODES" \
  --set "global.azure_storage.storage_account_name=$AZURE_STORAGE_ACCOUNT" \
  --set "global.azure_storage.storage_container_name=$TARGET_STORAGE_CONTAINER" \
  --set "global.azure_storage.sts_token=$TARGET_STS_TOKEN" \
  --set "global.azure_storage.connection_string=$STORAGE_CONNECTION_STRING" \
  --set "global.num_concurrent_tasks.value=$NUM_CONCURRENT_TASKS" \
  --set "global.api_components_use_dummy_data.value=$API_COMPONENTS_USE_DUMMY_DATA" | tee /tmp/helm-upgrade.log
  set +o pipefail
  set +u
}
# Keep retrying helm upgrade if it times out
while true; do
  helm_upgrade

  if ! grep -q "timed out waiting for the condition" /tmp/helm-upgrade.log; then
    break
  fi

  echo "Helm upgrade timed out, retrying..."
  sleep 5
done

export USE_TAILSCALE=${USE_TAILSCALE:-false}

if [ "$USE_TAILSCALE" == "true" ]; then
  if [ ! -z "$TS_CLIENT_ID" ] && [ ! -z "$TS_CLIENT_SECRET" ]; then
    $INFRADIR/k8/charts/tailscale/deploy.sh
  fi
fi

set +x

$SCRIPT_DIR/wait_until_agent_running.sh

# Try up to 10 times for both commands in a single loop
while true; do
  if $SCRIPT_DIR/wait_until_litellm_running.sh && $SCRIPT_DIR/set_llm_budget.sh; then
    break
  fi
  echo "LiteLLM setup failed, retrying..."
  sleep 5
done


if [ "$INCLUDE_NODE_VIZ" == "true" ]; then
  NODEVIZ_IP=$($SCRIPT_DIR/get_nodeviz_ip.sh)
  echo "Node-viz is accessible at: http://$NODEVIZ_IP:8080"
  set +x
fi

if [ "$ENABLE_PUBLIC_IP" == "true" ]; then
  API_HOSTNAME="$($SCRIPT_DIR/get_crs_endpoint.sh)"
  echo "API is accessible at: $API_HOSTNAME"
fi

if [ ! -z "$CRS_API_HOSTNAME" ]; then
  echo "API is accessible at: https://$CRS_API_HOSTNAME"
fi

fi

wait
