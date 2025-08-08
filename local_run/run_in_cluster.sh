#!/usr/bin/env bash
set -x
set -e

export currtime="$(($(date +%s) * 1000))"
if [ ! -z "$RUN_DUR_MS" ]; then
    export duetime="$(($currtime + $RUN_DUR_MS))"
    export RUN_DUR_MS=$RUN_DUR_MS
else
    export duetime="$(($currtime + 43200000))"
fi

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
SCRIPT_PARENT_DIR=$(dirname $SCRIPT_DIR)
CRS_ROOT="$SCRIPT_PARENT_DIR/"

if [ -z "$1" ]; then
    echo "Usage: $0 <target_url> <project_name> [base_commit] [reference_commit]"
    echo "Example: $0 https://github.com/aixcc-finals/example-libpng libpng"
    echo "         $0 https://github.com/aixcc-finals/example-libpng libpng <base_commit>"
    echo "         $0 https://github.com/aixcc-finals/example-libpng libpng <base_commit> <reference_commit>"
    exit 1
fi

TARGET_URL="${1%.git}"
PROJECT_NAME="$2"
BASE_COMMIT="$3"
REFERENCE_COMMIT="$4"

if [ -f "$CRS_ROOT/infra/tmp/.env" ]; then
    . $CRS_ROOT/infra/tmp/.env
fi
if [ -f "$CRS_ROOT/infra/tmp/.k8-env" ]; then
    . $CRS_ROOT/infra/tmp/.k8-env
fi

if [ -z "$CLUSTER_URL" ] && [ ! -z "$CLUSTER_IP" ]; then
    CLUSTER_URL="http://$CLUSTER_IP/"
fi

if [ -z "$CLUSTER_URL" ]; then
    #CLUSTER_URL="$(timeout 20 $CRS_ROOT/infra/scripts/get_crs_endpoint.sh)"
    #if [ -z "$CLUSTER_URL" ]; then
        CLUSTER_URL="$(timeout 20 $CRS_ROOT/infra/scripts/get_api_ip.sh)"
        if [ ! -z "$CLUSTER_URL" ]; then
            CLUSTER_URL="http://$CLUSTER_URL/"
        fi
    #fi

    if [ -z "$CLUSTER_URL" ]; then
        echo "Error: Failed to get cluster URL, make sure the cluster is deployed and you are connected to it"
        exit 1
    fi
fi


# strip / from the cluster url if it exists
CLUSTER_URL=${CLUSTER_URL%/}


export STORAGE_ACCOUNT='artiphishellcitiny'
export CONTAINER_NAME='targets'
export STORAGE_KEY=$TARGET_STS_TOKEN
export CONNECTION_STRING=$STORAGE_CONNECTION_STRING

export CRS_API_KEY_ID=${ARTIPHISHELL_API_USERNAME:-shellphish}
export CRS_API_TOKEN=${ARTIPHISHELL_API_PASSWORD:-!!!shellphish!!!}

GENERATE_CHALLENGE_TASK_REPO="${GENERATE_CHALLENGE_TASK_REPO:=https://github.com/shellphish-support-syndicate/aixcc-afc-generate-challenge-task.git}"
# Check if generate-challenge-task exists, if not clone it
if [ ! -d "$SCRIPT_DIR/generate-challenge-task" ]; then
    git clone $GENERATE_CHALLENGE_TASK_REPO "$SCRIPT_DIR/generate-challenge-task"
    pushd "$SCRIPT_DIR/generate-challenge-task"
        git checkout origin/custom
    popd
fi

# If base commit is not specified, get HEAD of the target repo
if [ -z "$BASE_COMMIT" ]; then
    BASE_COMMIT=$(git ls-remote "$TARGET_URL" HEAD | cut -f1)
fi

export DISABLE_VDS_TIMEOUT="${DISABLE_VDS_TIMEOUT:=1}"
export DISABLE_GP_TIMEOUT="${DISABLE_GP_TIMEOUT:=1}"

# Build the command with conditional reference commit
CMD="./generate-challenge-task.sh -c \"$CLUSTER_URL\" \
    -t \"$TARGET_URL\" \
    -b \"$BASE_COMMIT\" \
    -p \"$PROJECT_NAME\" \
    -v"

export CUSTOM_OSS_FUZZ_TARGETS_REPO="${CUSTOM_OSS_FUZZ_TARGETS_REPO:-}"
if [ ! -z "$CUSTOM_OSS_FUZZ_TARGETS_REPO" ]; then
    CUSTOM_OSS_FUZZ_TARGETS_REPO=$(echo "$CUSTOM_OSS_FUZZ_TARGETS_REPO" | sed 's|git@github.com:|https://github.com/|g')
    mkdir -p $SCRIPT_DIR/.shellphish
    CUSTOM_OSS_FUZZ_REPO="$SCRIPT_DIR/.shellphish/oss-fuzz"
    if [ ! -d "$CUSTOM_OSS_FUZZ_REPO"_org ]; then
        git clone https://github.com/google/oss-fuzz.git "$CUSTOM_OSS_FUZZ_REPO"_org
    fi
    rm -rf $CUSTOM_OSS_FUZZ_REPO || true
    cp -r "$CUSTOM_OSS_FUZZ_REPO"_org $CUSTOM_OSS_FUZZ_REPO
    if [ ! -d "$SCRIPT_DIR/.shellphish/oss-fuzz-targets" ]; then
        git clone "$CUSTOM_OSS_FUZZ_TARGETS_REPO" $SCRIPT_DIR/.shellphish/oss-fuzz-targets
        pushd $SCRIPT_DIR/.shellphish/oss-fuzz-targets
            # first, we check if git-lfs is installed
            if command -v git-lfs &> /dev/null; then
                echo "git-lfs is already installed, pulling LFS files"
            else
                # install it if not installed
                curl -s https://packagecloud.io/install/repositories/github/git-lfs/script.deb.sh | bash
                apt-get install git-lfs
            fi
            git lfs pull
        popd
    fi
    # pull the latest changes from the target repo (oss-fuzz-targets)
    pushd $SCRIPT_DIR/.shellphish/oss-fuzz-targets
        git fetch origin
        git reset --hard origin/HEAD
    popd

    rm -rf $CUSTOM_OSS_FUZZ_REPO/projects/
    cp -r $SCRIPT_DIR/.shellphish/oss-fuzz-targets/projects $CUSTOM_OSS_FUZZ_REPO/projects
    pushd $CUSTOM_OSS_FUZZ_REPO
        yq e ".shellphish_project_name = \"$PROJECT_NAME\"" -i projects/$PROJECT_NAME/project.yaml
        # WE DO NOT INCLUDE shellphish_docker_image in the project.yaml file as we will build it in cluster
        git add projects > /dev/null 2>&1
        git commit -m "Add shellphish oss-fuzz targets" >/dev/null 2>/dev/null || echo "Error committing changes"
    popd
    CMD="$CMD -o \"$CUSTOM_OSS_FUZZ_REPO\""
fi

if [ ! -z "$REFERENCE_COMMIT" ]; then
    CMD="$CMD -r \"$REFERENCE_COMMIT\""
fi
TAR_REPOS=$SCRIPT_DIR/generate-challenge-task/repo-tars

# Run the generate-challenge-task script
pushd "$SCRIPT_DIR/generate-challenge-task"
rm -rf $TAR_REPOS
if [ -z "$CRS_TASK_ID" ]; then
    export CRS_TASK_ID="CAFE0000-0000-0000-0000-000000000001"
fi
export RUN_DUR_MS=$RUN_DUR_MS
echo "export RUN_DUR_MS=$RUN_DUR_MS" >> ./.env
echo "$RUN_DUR_MS" > /tmp/.run_dur_ms
eval $CMD
cat task_crs.sh | tail -n1 | sed 's/.*-d //g' | sed "s/'//g" | jq .tasks\["0"\].task_id | sed 's/"//g' > $CRS_ROOT/.task_id

# Wait for /status endpoint to be reachable
echo "Waiting for /status endpoint to be reachable..."
curl --user "$CRS_API_KEY_ID:$CRS_API_TOKEN" -L "$CLUSTER_URL/status/"

while ! curl --user "$CRS_API_KEY_ID:$CRS_API_TOKEN" -sL "$CLUSTER_URL/status/" | jq -c '.ready' | grep -q true; do
    echo "Waiting for /status endpoint..."
    sleep 5
    curl --user "$CRS_API_KEY_ID:$CRS_API_TOKEN" -L "$CLUSTER_URL/status/"
done
echo "/status endpoint is now reachable"

# Waiting a bit bc pdt agent keeps not working
sleep 20

# Run the task
echo "Running the task..."

./task_crs.sh
