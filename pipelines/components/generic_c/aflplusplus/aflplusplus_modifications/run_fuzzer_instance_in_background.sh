#!/bin/bash

set -u

export DOCKER_EXTRA_ARGS="-v /shared:/shared -v /dev/shm/fuzztmp/$1:/tmp --memory 1G --cpu-quota 100000"

HARNESS_ID="${CP_HARNESS_ID}"
TARGET_DIR="${TARGET_DIR}"
INSTANCE_DIR=$(realpath "${INSTANCE_DIR}")

CMPLOG_TARGET_DIR="${CMPLOG_TARGET_DIR:-}"
INITIAL_SEEDS_DIR="${INITIAL_SEEDS_DIR:-}"

FUZZER_NAME="$1"
shift 1
FUZZER_EXTRA_ARGS_STRING="$@"

cd "${INSTANCE_DIR}"

export REL_BIN_PATH=$(yq ".harnesses.${HARNESS_ID}.binary" ./project.yaml)
WORKDIR=/work/
export HARNESS_BINARY="/${REL_BIN_PATH}"
export HARNESS_NAME=$(basename "${REL_BIN_PATH}")

mkdir -p ./work/sync ./work/initial_corpus

# if cmplog exists, create a copy of the binary with the cmplog extension
if [ -d "${CMPLOG_TARGET_DIR}" ]; then
    if [ ! -f "${REL_BIN_PATH}.cmplog" ]; then
        cp $CMPLOG_TARGET_DIR/"${REL_BIN_PATH}" "${REL_BIN_PATH}.cmplog"
    fi
fi

echo '' > ./work/initial_corpus/empty
echo 'fuzz' > ./work/initial_corpus/fuzz
if [ -d "${INITIAL_SEEDS_DIR}" ]; then
    find "${INITIAL_SEEDS_DIR}" -type f -exec cp -f {} ./work/initial_corpus/ \;
fi

cp /shellphish/aflpp/.env.project.fuzz ./.env.project; echo >> ./.env.project
cp /shellphish/aflpp/.env.docker.fuzz-merge ./.env.docker.prefix; echo >> ./.env.docker.prefix
echo "SHELLPHISH_CP_NAME=${CP_NAME}" >> .env.docker.prefix
echo "SHELLPHISH_HARNESS_BIN=${HARNESS_BINARY}" >> .env.docker.prefix

cp .env.docker.prefix .env.docker
echo "SHELLPHISH_FUZZER_NAME=${FUZZER_NAME}" >> .env.docker
echo "SHELLPHISH_EXTRA_ARGS_STRING=${FUZZER_EXTRA_ARGS_STRING}" >> .env.docker

# move the harness out of the way and replace it with our bash script
cp ${REL_BIN_PATH}.original ${REL_BIN_PATH}.${FUZZER_NAME}.shellphish
cp -f /shellphish/aflpp/shellphish_aflpp_fuzz.sh "${REL_BIN_PATH}"

rm -f "${INSTANCE_DIR}/work/$FUZZER_NAME.up"

./run.sh -x run_pov .env.docker "$HARNESS_NAME" 2>&1 | tee ${INSTANCE_DIR}/$1.log &

set -x
echo "loop starting"
while [ ! -f "${INSTANCE_DIR}/work/$FUZZER_NAME.up" ]; do echo "sleeping..."; sleep 1; done
echo "loop finished"
