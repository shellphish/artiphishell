#!/usr/bin/env bash

set -ex

if [ -z "$1" ]; then
# pull - Pull as many images as possible from `master nightly` and then build the rest on top
# build - Pull only the base images from `master nightly` and build the rest from scratch

# build-all / local-build - Build everything from scratch
# build-all-for-pipeline - Build everything from scratch for a pipeline run
    echo "Usage: $0 pull|build|build-all|build-all-for-pipeline|local-build|remote [image-aixcc-<component> ...]"
    echo "       pull: Pull as many images as possible from master nightly and then build the rest on top"
    echo "       build: Pull only the base images from master nightly and build the rest from scratch"
    echo "       build-all: Build everything from scratch"
    echo "       local-build: Alias for build-all"
    echo "       build-all-for-pipeline: Build everything from scratch for a pipeline run"
    echo "       remote: Same as build-all-for-pipeline but pushes images to ghcr.io/shellphish-support-syndicate/"
    exit 1
fi

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
export SHELLPHISH_CRS_DIR=$(realpath $SCRIPT_DIR/../)
pushd $SHELLPHISH_CRS_DIR
echo $PWD

export DOCKER_BINARY=$(which docker)

export GIT_BRANCH=$(git rev-parse --abbrev-ref HEAD)

if [ "$USE_DOCKER_CACHE" == "true" ]; then
  export PATH="$SHELLPHISH_CRS_DIR/local_run/tools/bin:$PATH"
  export DOCKER_CACHE_REGISTRY="artiphishelltiny.azurecr.io"
  export PUSH_DOCKER_CACHE="true"
  export USE_PARALLEL_DOCKER_COMPOSE="true"

  docker reset-build-cache || true
fi


USE_LOCAL_REGISTRY=""
BUILD_BASE=""
export PUSH=""
if [ ! -z "$DO_PUSH" ]; then
    export PUSH="--push"
fi

CMD="$1"

export EXTERNAL_REGISTRY="${EXTERNAL_REGISTRY:-ghcr.io/shellphish-support-syndicate}"

if [ "$CMD" == 'remote' ]; then
    export OUTPUT_IMAGE_PREFIX="${EXTERNAL_REGISTRY}/"
    CMD="build-all-for-pipeline"
    export PUSH="--push"
fi

ls -la ./libs || true

# TODO make this configurable
export TAG_ALL="true"


if [ "$CMD" == 'pull' ] || [ "$CMD" == 'build' ]; then
    # For these we are going to pull the base images rather than building them
    export IMAGE_PREFIX="${EXTERNAL_REGISTRY}/"
    if [ "$CMD" == 'local-build' ]; then
        export OUTPUT_IMAGE_PREFIX=""
    fi
    ./local_run/generate_local_docker_compose.sh > ./docker-compose.yaml
    # ./crs/generate_docker_compose.sh > ./docker-compose.yaml
else
    # Otherwise we are going to build in the "localhost" namespace so we don't pull any old base image tags
    export IMAGE_PREFIX="localhost:5000/"
    # But due to limitations in docker compose we need to push to a local registry
    USE_LOCAL_REGISTRY="true"
    if [ "$CMD" == 'build-all-for-pipeline' ]; then
        export OUTPUT_IMAGE_PREFIX="${EXTERNAL_REGISTRY}/"
    fi
    ./local_run/generate_local_docker_compose.sh > ./docker-compose.yaml
fi

if [ "$CMD" == 'build-all' ] || [ "$CMD" == 'build-all-for-pipeline' ] || [ "$CMD" == 'local-build' ]; then
    BUILD_BASE="true"
fi

cat ./docker-compose.yaml
shift || true

if [ ! -z "$USE_LOCAL_REGISTRY" ]; then
    echo "Starting the local registry (if not running)"
    docker rm -f aixcc-local-build-registry || true;
    sleep 5;
    docker run --rm -d \
        --name aixcc-local-build-registry \
        -v /opt/registry/:/var/lib/registry \
        -p 127.0.0.1:5000:5000 \
        -p [::1]:5000:5000 \
        registry:2 ;
    sleep 5;
fi

rm /tmp/prebuild_instrumentation_images.success || true
rm /tmp/push_static_images.success || true

########### PUSH STATIC IMAGES ###########
export PUSH="$PUSH"
if [ ! -z "$PUSH" ]; then
  ( (
    set -ex
    $SHELLPHISH_CRS_DIR/local_run/push_static_images.sh
    touch /tmp/push_static_images.success
  ) 2>&1 | tee /tmp/push_static_images.log ) &
else
  touch /tmp/push_static_images.success
fi

( (
  set -ex
  $SHELLPHISH_CRS_DIR/local_run/prebuild_instrumentation_images.sh
  touch /tmp/prebuild_instrumentation_images.success
) 2>&1 | tee /tmp/prebuild_instrumentation_images.log ) &

set -ex

export DOCKER_CACHE_MUST_DOWNLOAD="true"

if [ ! -z "$BUILD_BASE" ]; then
  docker build $ADDITIONAL_DOCKER_ARGS -t ${EXTERNAL_REGISTRY}/aixcc-dependencies-base:latest ./ -f ./docker/Dockerfile.dependencies-base $PUSH
  docker tag ${EXTERNAL_REGISTRY}/aixcc-dependencies-base:latest ${IMAGE_PREFIX}aixcc-dependencies-base:latest

  docker build $ADDITIONAL_DOCKER_ARGS -t ${EXTERNAL_REGISTRY}/aixcc-component-base:latest ./ -f ./docker/Dockerfile.component-base --build-arg IMAGE_PREFIX=${IMAGE_PREFIX} $PUSH
  docker tag ${EXTERNAL_REGISTRY}/aixcc-component-base:latest ${IMAGE_PREFIX}aixcc-component-base:latest

else
  if [ ! -z "$BASE_IMAGE_CACHE_REGISTRY" ]; then
    timeout 1800 docker pull ${BASE_IMAGE_CACHE_REGISTRY}/aixcc-dependencies-base:latest
    docker tag ${BASE_IMAGE_CACHE_REGISTRY}/aixcc-dependencies-base:latest ${EXTERNAL_REGISTRY}/aixcc-dependencies-base:latest
    timeout 1800 docker pull ${BASE_IMAGE_CACHE_REGISTRY}/aixcc-component-base:latest
    docker tag ${BASE_IMAGE_CACHE_REGISTRY}/aixcc-component-base:latest ${EXTERNAL_REGISTRY}/aixcc-component-base:latest
  else
    timeout 1800 docker pull ${EXTERNAL_REGISTRY}/aixcc-dependencies-base:latest
    timeout 1800 docker pull ${EXTERNAL_REGISTRY}/aixcc-component-base:latest
  fi

  docker tag ${EXTERNAL_REGISTRY}/aixcc-dependencies-base:latest ${IMAGE_PREFIX}aixcc-dependencies-base:latest
  docker tag ${EXTERNAL_REGISTRY}/aixcc-component-base:latest ${IMAGE_PREFIX}aixcc-component-base:latest
fi

docker tag ${IMAGE_PREFIX}aixcc-dependencies-base:latest aixcc-dependencies-base:latest
docker tag ${IMAGE_PREFIX}aixcc-component-base:latest aixcc-component-base:latest
docker tag ${IMAGE_PREFIX}aixcc-dependencies-base:latest ${OUTPUT_IMAGE_PREFIX}aixcc-dependencies-base:latest
docker tag ${IMAGE_PREFIX}aixcc-dependencies-base:latest ${EXTERNAL_REGISTRY}/aixcc-dependencies-base:latest
docker tag ${IMAGE_PREFIX}aixcc-component-base:latest ${OUTPUT_IMAGE_PREFIX}aixcc-component-base:latest
docker tag ${IMAGE_PREFIX}aixcc-component-base:latest ${EXTERNAL_REGISTRY}/aixcc-component-base:latest

if [ ! -z "$USE_LOCAL_REGISTRY" ]; then
  docker push ${IMAGE_PREFIX}aixcc-component-base:latest
  docker push ${IMAGE_PREFIX}aixcc-dependencies-base:latest
fi

if [ ! -z "$PUSH" ]; then
  docker push ${OUTPUT_IMAGE_PREFIX}aixcc-component-base:latest
  docker push ${OUTPUT_IMAGE_PREFIX}aixcc-dependencies-base:latest
fi

mv ./.dockerignore ./.dockerignore.bak || true
docker build $ADDITIONAL_DOCKER_ARGS -t ${OUTPUT_IMAGE_PREFIX}aixcc-libs:latest ./libs -f ./libs/Dockerfile --build-arg IMAGE_PREFIX=${IMAGE_PREFIX} $PUSH
mv ./.dockerignore.bak ./.dockerignore || true

docker tag ${OUTPUT_IMAGE_PREFIX}aixcc-libs:latest aixcc-libs:latest
docker tag ${OUTPUT_IMAGE_PREFIX}aixcc-libs:latest ${IMAGE_PREFIX}aixcc-libs:latest
docker tag ${OUTPUT_IMAGE_PREFIX}aixcc-libs:latest ${EXTERNAL_REGISTRY}/aixcc-libs:latest

unset DOCKER_CACHE_MUST_DOWNLOAD

# pushd ./aixcc-infra/aixcc-sc-capi
# docker compose build $PUSH
# popd

# if [ "$1" == "remote" ]; then
#     docker build $ADDITIONAL_DOCKER_ARGS -t ${IMAGE_PREFIX}aixcc-leader:latest ./pipelines -f ./pipelines/meta-components/leader-scripts/Dockerfile --build-arg IMAGE_PREFIX=${IMAGE_PREFIX} $PUSH
#     docker tag ${IMAGE_PREFIX}aixcc-leader:latest aixcc-leader:latest
# fi
#docker build -t image-aixcc-opwnai-base:latest ./pipelines/ -f ./pipelines/components/common/opwnai/Dockerfile

rm /tmp/build_infra.success || true

# Run all builds in parallel and wait for completion
(
  (
  set -xe
  env | grep PUSH || true

  # Run services builds in parallel
  $SHELLPHISH_CRS_DIR/services/telemetry_db/build_all.sh $PUSH &
  database_pid=$!

  $SHELLPHISH_CRS_DIR/infra/ci/monitor/build.sh $PUSH &
  monitor_pid=$!

  $SHELLPHISH_CRS_DIR/aixcc-infra/competition-server/meta-build.sh $PUSH &
  competition_server_pid=$!

  $SHELLPHISH_CRS_DIR/infra/litellm/build.sh $PUSH &
  litellm_pid=$!

  $SHELLPHISH_CRS_DIR/services/vllm/build.sh $PUSH &
  vllm_pid=$!

  $SHELLPHISH_CRS_DIR/services/image_puller/build.sh $PUSH &
  image_puller_pid=$!

  sleep 5

  # These require a root level .dockerignore file, so give each a chance to pick up their source before starting the next
  $SHELLPHISH_CRS_DIR/infra/agent/build.sh $PUSH
  $SHELLPHISH_CRS_DIR/infra/api/build.sh $PUSH

  # Wait for each process and check its exit status
  for pid in $database_pid $monitor_pid $competition_server_pid $litellm_pid $vllm_pid; do
    if ! wait $pid; then
      echo "Build process $pid failed"
      exit 1
    fi
  done
  wait
  touch /tmp/build_infra.success
) 2>&1 | tee /tmp/build_infra.log )

rm /tmp/build_crs.success || true
(
  set -ex
  env | grep PUSH || true
docker compose -f ./docker-compose.yaml --profile local build $ADDITIONAL_DOCKER_ARGS $@
if [[ ! -z "$TAG_ALL" ]]; then
    echo "===== RETAGGING ALL IMAGES PLEASE STAND BY ====="
    export OUTPUT_IMAGE_PREFIX=""
    ./local_run/generate_local_docker_compose.sh > ./docker-compose.yaml
    docker compose -f ./docker-compose.yaml --profile local build -q $ADDITIONAL_DOCKER_ARGS $@
    if [[ "$IMAGE_PREFIX" != "${EXTERNAL_REGISTRY}/" ]]; then
        export OUTPUT_IMAGE_PREFIX="${EXTERNAL_REGISTRY}/"
        ./local_run/generate_local_docker_compose.sh > ./docker-compose.yaml
        docker compose -f ./docker-compose.yaml --profile local build -q $ADDITIONAL_DOCKER_ARGS $@
    fi
fi
if [[ -n "$PUSH" ]]; then
    docker compose -f ./docker-compose.yaml --profile local push -q
fi
touch /tmp/build_crs.success
) 2>&1 | tee /tmp/build_crs.log

wait

rm docker-compose.yaml

if [ ! -f /tmp/build_crs.success ]; then
  echo "==== Build crs failed ==="
  cat /tmp/build_crs.log
  exit 1
fi

if [ ! -f /tmp/prebuild_instrumentation_images.success ]; then
  echo "==== Prebuild instrumentation images failed ==="
  cat /tmp/prebuild_instrumentation_images.log
  exit 1
fi

if [ ! -f /tmp/push_static_images.success ]; then
  echo "==== Push static images failed ==="
  cat /tmp/push_static_images.log
  exit 1
fi

if [ ! -f /tmp/build_infra.success ]; then
  echo "==== Build infra failed ==="
  cat /tmp/build_infra.log
  exit 1
fi

popd