#!/bin/bash

set -e
set -x

CUR_DIR=$(dirname $(realpath "${0}"))
PARENT=$(realpath "$CUR_DIR/../")
SNAPCHANGE=$(realpath "$PARENT/snapchange")

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <target_program>"
    exit 1
fi

TARGET=$1
if [ ! -d "$TARGET" ]; then
    echo "$TARGET is not a valid directory"
    exit 1
fi

CP_PATH=$(realpath "$TARGET")
CP_NAME=$(basename "$CP_PATH")
echo "[*] Going to use CP in $CP_PATH. Make sure its compiled with the correct config"

pushd "$PARENT"
DOCKER_IMAGE_NAME="aixcc-snapchange-fuzz"
docker build -t "$DOCKER_IMAGE_NAME" .
popd

HARNESS_BINARY=$(yq ".harnesses.id_3.binary" ${CP_PATH}/project.yaml | tr -d '"')
HARNESS_SOURCE=$(yq ".harnesses.id_3.source" ${CP_PATH}/project.yaml | tr -d '"')
KERNEL_RELPATH=$(yq '.cp_sources | keys | .[0]' ${CP_PATH}/project.yaml)

docker run \
    -d \
    --rm \
    --privileged \
    -v "$CP_PATH":/cp \
    --name "$CP_NAME" \
    -it \
    "$DOCKER_IMAGE_NAME" /bin/bash

docker exec -it "$CP_NAME" /bin/bash -c "clang -c -o /cp/snapchange_lib.o /snapchange_modifications/snapchange_lib.c && ar rcs /cp/libsnapchange.a /cp/snapchange_lib.o"
docker exec -it "$CP_NAME" /bin/bash -c "clang /cp/${HARNESS_SOURCE} /snapchange_modifications/coverage_harness.c -ggdb -no-pie -fsanitize-coverage=inline-8bit-counters -L/cp -lsnapchange -Wl,-rpath=/cp -o /cp/$HARNESS_BINARY"

docker exec -it "$CP_NAME" /bin/bash -c "cd /snapchange/fuzzer && ./make_example.sh /cp/$HARNESS_BINARY /cp/src/$KERNEL_RELPATH"
echo "Now run: /workdir/fuzz.sh"