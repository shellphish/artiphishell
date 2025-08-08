#!/bin/bash

set -e

INFRA_DIR=$(realpath $(dirname $0)/../)
ROOT_DIR=$(realpath $INFRA_DIR/../)
cd $INFRA_DIR

#TF_VAR_ARM_SUBSCRIPTION_ID	Azure subscription ID
#TF_VAR_ARM_TENANT_ID	Azure tenant ID
#TF_VAR_ARM_CLIENT_ID	Azure client ID (service principal account)
#TF_VAR_ARM_CLIENT_SECRET	Azure client ID secret
#CRS_API_HOSTNAME	The hostname you want to assign to your API. Exmaple: teamX-api
#TS_CLIENT_ID	Tailscale oauth client ID (provided by the Organizers)
#TS_CLIENT_SECRET	Tailscale oauth client secret (provided by the Organizers)
#TS_OP_TAG	Tailscale operator tag (provided by the Organizers)
#COMPETITION_API_KEY_ID	HTTP basic auth username for the competition API (provided by the Organizers)
#COMPETITION_API_KEY_TOKEN	HTTP basic auth password for the competition API (provided by the Organizers)
#CRS_KEY_ID	HTTP basic auth username for the CRS API
#CRS_KEY_TOKEN	HTTP basic auth password for the CRS API
#GHCR_AUTH	Base64 encoded credentials for GHCR

export GITHUB_REF=$(git rev-parse --abbrev-ref HEAD)

if [ -z "$TS_CLIENT_ID" ]; then
    echo "❌ Error: TS_CLIENT_ID is not set"
    exit 1
fi
if [ -z "$TS_CLIENT_SECRET" ]; then
    echo "❌ Error: TS_CLIENT_SECRET is not set"
    exit 1
fi
if [ -z "$TS_OP_TAG" ]; then
    echo "❌ Error: TS_OP_TAG is not set"
    exit 1
fi

# TF_VAR_ARM_CLIENT_ID and TF_VAR_ARM_CLIENT_SECRET are optional if you are logged in with `az login`

if [ -z "$TF_VAR_ARM_CLIENT_ID" ] || [ -z "$TF_VAR_ARM_CLIENT_SECRET" ]; then
    if ! az account show > /dev/null 2>&1; then
        echo "❌ Error: You are not logged in to Azure, please run `az login` or set TF_VAR_ARM_CLIENT_ID and TF_VAR_ARM_CLIENT_SECRET envs"
        exit 1
    fi
fi

if [ -z "$TF_VAR_ARM_TENANT_ID" ]; then
    echo "❌ Error: TF_VAR_ARM_TENANT_ID is not set"
    exit 1
fi
if [ -z "$TF_VAR_ARM_SUBSCRIPTION_ID" ]; then
    echo "❌ Error: TF_VAR_ARM_SUBSCRIPTION_ID is not set"
    exit 1
fi

if [ -z "$CRS_API_HOSTNAME" ]; then
    echo "❌ Error: CRS_API_HOSTNAME is not set"
    exit 1
fi

if [ -z "$COMPETITION_API_KEY_ID" ]; then
    echo "❌ Error: COMPETITION_API_KEY_ID is not set"
    exit 1
fi
if [ -z "$COMPETITION_API_KEY_TOKEN" ]; then
    echo "❌ Error: COMPETITION_API_KEY_TOKEN is not set"
    exit 1
fi
if [ -z "$COMPETITION_API_URL" ]; then
    echo "❌ Error: COMPETITION_API_URL is not set"
    exit 1
fi

if [ -z "$CRS_KEY_ID" ]; then
    echo "❌ Error: CRS_KEY_ID is not set"
    exit 1
fi
if [ -z "$CRS_KEY_TOKEN" ]; then
    echo "❌ Error: CRS_KEY_TOKEN is not set"
    exit 1
fi

# GHCR_AUTH is optional

if [ -z "$CRS_API_URL" ]; then
    export CRS_API_URL="https://$CRS_API_HOSTNAME"
fi

# ==== CONFIGURATION DEFAULTS ====

if [ -z "$NUM_USER_NODES" ]; then
    # Starting Number of User Nodes at deployment
    export NUM_USER_NODES=1
fi
if [ -z "$MAX_USER_NODES" ]; then
    export MAX_USER_NODES=6
fi
if [ -z "$NUM_FUZZER_NODES" ]; then
    # Starting Number of Fuzzer Nodes at deployment
    export NUM_FUZZER_NODES=0
fi
if [ -z "$MAX_FUZZER_NODES" ]; then
    export MAX_FUZZER_NODES=6
fi
if [ -z "$USER_VM_SIZE" ]; then
    # Size of User Nodes
    export USER_VM_SIZE="standard_D32s_v3"
fi
if [ -z "$FUZZER_VM_SIZE" ]; then
    # Size of Fuzzer Nodes
    export FUZZER_VM_SIZE="standard_D32s_v3"
fi
if [ -z "$CRITICAL_VM_SIZE" ]; then
    # Size of Critical Nodes
    export CRITICAL_VM_SIZE="standard_D16s_v3"
fi

export NO_EXTERNAL_REGISTRY=${NO_EXTERNAL_REGISTRY:-true}
export EXCLUDE_GITHUB_CREDENTIALS=${EXCLUDE_GITHUB_CREDENTIALS:-true}
export INCLUDE_CI_PODS=${INCLUDE_CI_PODS:-false}
export INCLUDE_NODE_VIZ=${INCLUDE_NODE_VIZ:-true}
export NO_PUBLIC_IP=${NO_PUBLIC_IP:-false}

export DEPLOYMENT_NAME=${DEPLOYMENT_NAME:-default}

$INFRA_DIR/scripts/print_run_config.sh || true

read -p "Press Enter to continue..." -t 30 || true
echo ""

set -x

rm $INFRA_DIR/tmp/.*env -f || true
rm $INFRA_DIR/tmp/*env -f || true

# First create all required credentials/azure rg/storage account/etc
$INFRA_DIR/scripts/create_sp.sh

sleep 20

DID_BUILD=false

# If both --skiptf and --skipinstall are provided:
if [[ "$*" =~ "--skiptf" ]] && [[ "$*" =~ "--skipinstall" ]]; then
    $INFRA_DIR/scripts/create_deployment.sh $DEPLOYMENT_NAME --skipinstall --skiptf --only-registry
fi

if [[ "$*" =~ "--build" ]] || [[ "$*" =~ "--ci-build" ]]; then
    if [[ ! "$*" =~ "--skiptf" ]]; then
        # Deploy the registry first so we can start pushing images asap
        $INFRA_DIR/scripts/create_deployment.sh $DEPLOYMENT_NAME --skipinstall --only-registry
        . tmp/.k8-env
        export EXTERNAL_REGISTRY="$LOGIN_SERVER"
        export EXTERNAL_REGISTRY_USERNAME="$USERNAME"
        export EXTERNAL_REGISTRY_PASSWORD="$PASSWORD"
    else
        pushd $INFRA_DIR/tf
        set +x
        . tmp/.env
        set -x
        export EXTERNAL_REGISTRY=$(terraform output -raw acr_login_server)
        export EXTERNAL_REGISTRY_USERNAME=$(terraform output -raw acr_admin_username)
        export EXTERNAL_REGISTRY_PASSWORD=$(terraform output -raw acr_admin_password)

        popd
    fi

    # Now start the registry push in parallel
    if [[ "$*" =~ "--build" ]]; then
        echo "📦 Building images locally"
        docker login $EXTERNAL_REGISTRY -u $EXTERNAL_REGISTRY_USERNAME -p $EXTERNAL_REGISTRY_PASSWORD
        $ROOT_DIR/local_scripts/rebuild_local.sh remote
    elif [[ "$*" =~ "--ci-build" ]]; then
        set +x
        echo "☁️ Building images in CI"
        echo " ☁️ NOTE: This will use the current remote branch of https://github.com/shellphish-support-syndicate/artiphishell/tree/$GITHUB_REF to build the images"
        read -p "Press Enter to continue..." -t 30 || true
        echo ""
        set -x
        $INFRA_DIR/scripts/ci/ci_build_to_cluster.sh /tmp/build_id
        DID_BUILD=true
        sleep 10
    fi
fi
exit 1

# ==== TERRAFORM K8S CLUSTER DEPLOYMENT ====

if [[ ! "$*" =~ "--skiptf" ]]; then
    # Now do the terraform deployment
    $INFRA_DIR/scripts/create_deployment.sh $DEPLOYMENT_NAME --skipinstall
fi


# ==== Wait Until Build is Done ====

if [ -f /tmp/build_id ] && [ "$DID_BUILD" = true ]; then
    if [[ "$*" =~ "--restart" ]]; then
        # Bring down in parallel with the build
        $INFRA_DIR/scripts/stop_helm.sh || true
    fi

    BUILD_ID=$(cat /tmp/build_id)
    $INFRA_DIR/scripts/ci/ci_wait_for_build.sh $BUILD_ID
    rm /tmp/build_id
fi

if [[ "$*" =~ "--skipinstall" ]]; then
    exit 0
fi

# ==== Install Helm Application ====

if [[ ! "$*" =~ "--skipinstall" ]]; then
    ARGS="--skiptf"
    if [[ "$*" =~ "--restart" ]]; then
        ARGS="--skiptf --restart"
    fi
    # Finally install the actual helm application into the cluster
    $INFRA_DIR/scripts/create_deployment.sh $DEPLOYMENT_NAME $ARGS
fi
