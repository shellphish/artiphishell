#!/bin/sh
# This file is meant to be sourced by the pipeline task

RAND=$(head /dev/urandom -c 5 | xxd -p | tr -d '\n')

CONTAINER_NAME="aixcc-jazzer-${TARGET_ID}-${TASK_NAME}-${RAND}-${index}"
echo
echo
echo
echo "========= Starting Jazzer Fuzzer: ${CONTAINER_NAME} ========"

echo "foo" > /tmp/foo

set -x
(
  # Remove lines which contain FUZZ_INDEX in $INSTANCE_DIR/.env.docker
  sed -i '/FUZZ_INDEX/d' "$INSTANCE_DIR/.env.docker"
  echo "FUZZ_INDEX=${index}" >> "$INSTANCE_DIR/.env.docker"

  sed -i '/JAVA_OPTS/d' "$INSTANCE_DIR/.env.docker"
  echo 'JAVA_OPTS=-Xmx2770m' >> "$INSTANCE_DIR/.env.docker"

  sed -i '/CP_DOCKER_EXTRA_ARGS/d' "$INSTANCE_DIR/.env.project"
  echo 'CP_DOCKER_EXTRA_ARGS=" -v '"${CONTAINER_INPUTS}"':/inputs -v '"${CONTAINER_OUTPUTS}"':/crashes --name '"${CONTAINER_NAME}"' --memory 3G --cpu-quota 42000"'  \
    >> "$INSTANCE_DIR/.env.project"

  ./run.sh run_pov /tmp/foo "${CP_HARNESS_NAME}" &

  sleep 5 # wait for the container to actually launch with our settings
)
set +x
