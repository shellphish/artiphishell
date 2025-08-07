#!/usr/bin/env bash
set -x
set -e

SCRIPT_PARENT_DIR=$(dirname $( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd ))
trap "trap - SIGTERM && kill -- -$$" SIGINT SIGTERM EXIT

TARGET_REPOS="${TARGET_REPOS:=ghcr.io/aixcc-sc/mock-cp:v3.0.2 ghcr.io/aixcc-sc/challenge-004-nginx-cp:v1.0.0 ghcr.io/aixcc-sc/challenge-002-jenkins-cp:v3.1.0}"
TARGET_MAKE="${TARGET_MAKE:=mock-cp jenkins-cp nginx-cp}"
TARGET_SOURCE_REPO="${TARGET_SOURCE_REPO:=idk}"
DO_PDL_UNLOCK="${DO_PDL_UNLOCK:=true}"

pushd $SCRIPT_PARENT_DIR/meta-components/aixcc-sc-capi/
#make clean
if [ ! -f ./env  ]
then
    cp env.example env
fi
sudo rm -rf cp_root /shared/ /crs_scratch/
if [ ! -d cp_root ]; then
    # this is all for just the mock-cp target

    for MAKE_CMD in $TARGET_MAKE
    do
        case $MAKE_CMD in
            mock-cp | jenkins-cp | nginx-cp)
                make $MAKE_CMD
                ;;
            *)
                # Copy shit from the repo
                # Hard coding the path for the CI, fix if you care about it
                echo $PWD
                ROOT_DIR=/home/runner/actions-runner/_work/pipelines/pipelines/pipelines-real/meta-components/aixcc-sc-capi
                HOST_CAPI_LOGS=$ROOT_DIR/capi_logs
                HOST_CP_ROOT_DIR=$ROOT_DIR/cp_root
                mkdir -p $HOST_CAPI_LOGS
                mkdir -p $HOST_CP_ROOT_DIR
                rm -rf $HOST_CP_ROOT_DIR/$MAKE_CMD
                git clone $TARGET_SOURCE_REPO $HOST_CP_ROOT_DIR/$MAKE_CMD
                cd $HOST_CP_ROOT_DIR/$MAKE_CMD && make cpsrc-prepare
                cd $ROOT_DIR
                ;;
        esac
    done

    # if cp root exists
    if [ -d "./cp_root" ]; then
        # YEP THAT'S RIGHT FOLKS, YOU NEED SUDO BECAUSE NOTHING MAKES SENSE
        sudo chown -R 1000:1000 ./cp_root
    fi
fi
make down-volumes
WEB_CONCURRENCY=5 docker compose up -d

# wait until all three capi containers are running and we can talk to the capi dind docker container
while true
do
    if [ $(docker ps -f status=running | grep aixcc-sc-capi | wc -l) -eq 3 ] && docker exec -t aixcc-sc-capi-capi-1 docker images
    then
        break
    fi
    echo "Waiting until all three capi containers are running and we can talk to the capi dind docker container"
    sleep 1s
done

for target in $TARGET_REPOS
do
    if [ $(docker exec -t aixcc-sc-capi-capi-1 docker images -f reference=$target | wc -l) -eq 1 ]
    then
        echo "yeeting $target into the capi dind docker"
        docker image save "$target" | docker exec -i aixcc-sc-capi-capi-1 docker image load
    fi
done

popd

# set up APIs that are needed
# pushd $SCRIPT_PARENT_DIR/apis

# docker compose --profile kb up -d

# popd

pushd $SCRIPT_PARENT_DIR

if [ "$DO_PDL_UNLOCK" ==  "true" ]
then
    pdl --unlock || rm -rf pipeline.lock
fi
pdl --no-lockstep $PDL_ARGS --name CRS
if [ "$SHOULD_INJECT" == "true" ]; then
    eval "$PRE_RUN_EXEC"
fi
LITELLM_KEY=${LITELLM_KEY:-sk-artiphishell}
AIXCC_LITELLM_HOSTNAME=${AIXCC_LITELLM_HOSTNAME:-http://beatty.unfiltered.seclab.cs.ucsb.edu:4000/}
DISABLE_VDS_TIMEOUT=${DISABLE_VDS_TIMEOUT:-0}
DISABLE_GP_TIMEOUT=${DISABLE_GP_TIMEOUT:-0}
ROUND_TIME_SECONDS=${ROUND_TIME_SECONDS:-14400}
EXTRA_ENV=${EXTRA_ENV:-}

RETRIEVAL_API=http://beatty.unfiltered.seclab.cs.ucsb.edu:48751
EMBEDDING_API=http://beatty.unfiltered.seclab.cs.ucsb.edu:49152

pd $EXTRA_ENV --global-script-env "AIXCC_LITELLM_HOSTNAME=$AIXCC_LITELLM_HOSTNAME" \
              --global-script-env "DISABLE_GP_TIMEOUT=$DISABLE_GP_TIMEOUT"  \
              --global-script-env "DISABLE_VDS_TIMEOUT=$DISABLE_VDS_TIMEOUT" \
              --global-script-env "ROUND_TIME_SECONDS=$ROUND_TIME_SECONDS" \
              --global-script-env "RETRIEVAL_API=$RETRIEVAL_API" \
              --global-script-env "EMBEDDING_API=$EMBEDDING_API" \
              --global-script-env "LITELLM_KEY=$LITELLM_KEY" 1>/tmp/pydatatask-$(whoami)-agent-output-$(date +'%Y-%m-%d-%H-%M-%S') 2>&1 &
AGENT_PID=$!
echo $AGENT_PID > /tmp/pdt-run-id

if [ "$DO_PDL_UNLOCK" ==  "true" ]
then
    ./local_run/ingest.sh &
    sleep 2
fi

# Check if SHOULD_INJECT == "true"
if [ "$SHOULD_INJECT" == "true" ]; then
    ./local_run/inject_crash.sh &
fi

/bin/bash ./local_run/ci_fix_docker_created.bash &

ipython --pdb -m pydatatask.cli.main -- $EXTRA_ENV --global-script-env "AIXCC_LITELLM_HOSTNAME=$AIXCC_LITELLM_HOSTNAME" \
                                                   --global-script-env "DISABLE_GP_TIMEOUT=$DISABLE_GP_TIMEOUT"  \
                                                   --global-script-env "DISABLE_VDS_TIMEOUT=$DISABLE_VDS_TIMEOUT" \
                                                   --global-script-env "ROUND_TIME_SECONDS=$ROUND_TIME_SECONDS" \
                                                   --global-script-env "RETRIEVAL_API=$RETRIEVAL_API" \
                                                   --global-script-env "EMBEDDING_API=$EMBEDDING_API" \
                                                   --global-script-env "LITELLM_KEY=$LITELLM_KEY" \
                                                   --verbose --debug-trace run --forever

if [ ! -f /tmp/pdt_magic ]; then
    kill -INT $AGENT_PID
fi
wait
popd
