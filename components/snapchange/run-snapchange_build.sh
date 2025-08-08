#!/bin/bash

set -x
set -e
set -u
set -o pipefail

# these exports are together with the `-u` flag to ensure that the inputs are correctly set
export PROJECT_ID="${PROJECT_ID}"
export TARGET_WITH_SOURCES="${TARGET_WITH_SOURCES}"
export KERNEL_RELPATH="${KERNEL_RELPATH}"
export SNAPCHANGE_BUILT_TARGET="${SNAPCHANGE_BUILT_TARGET}"

BASE_IMAGE=$(yq ".docker_image" "${TARGET_WITH_SOURCES}/project.yaml" | tr -d '"')

export DOCKER_IMAGE_NAME="aixcc-snapchange-${PROJECT_ID}"

TEMP_DIR=/shared/snapchange/fuzz/snapchange_build/"${PROJECT_ID}"
mkdir -p /shared/snapchange/fuzz/snapchange_build/

rsync --delete -ra "${TARGET_WITH_SOURCES}/" ${TEMP_DIR}/
(
# Build the kernel with the necessary configs
cd "${TEMP_DIR}/${KERNEL_RELPATH}"
if [ ! -f .config ]; then
    # realistically this should never happen in the competition
    # but one of our testing targets doesn't have one T_T
    make defconfig
fi
./scripts/kconfig/merge_config.sh .config /snapchange/snapchange_modifications/snapchange.config
# make olddefconfig
./scripts/kconfig/merge_config.sh .config /snapchange/snapchange_modifications/snapchange.config
git apply /snapchange/snapchange_modifications/serialize_tipc.patch || true

clang -c -o /snapchange/snapchange_modifications/snapchange_lib.o /snapchange/snapchange_modifications/snapchange_lib.c
ar rcs /snapchange/snapchange_modifications/liblinkagainstharness.a /snapchange/snapchange_modifications/snapchange_lib.o

cd "${TEMP_DIR}"

mkdir -p ./shellphish
cp /snapchange/snapchange_modifications/coverage_harness.c ./shellphish/
cp /snapchange/snapchange_modifications/liblinkagainstharness.a ./shellphish/

cp /snapchange/snapchange_modifications/.env.docker ./.env.docker

docker pull $BASE_IMAGE >/dev/null 2>&1 || true
resp=$(docker image inspect $BASE_IMAGE >/dev/null 2>&1 && echo yes || echo no)
if test $resp = "no"; then
    docker build -t $BASE_IMAGE .
fi
docker build --build-arg=BASE_IMAGE="${BASE_IMAGE}" \
                -f /snapchange/snapchange_modifications/Dockerfile.extensions \
                -t "$DOCKER_IMAGE_NAME" .
./run.sh build

cd "$TEMP_DIR/$KERNEL_RELPATH"

BZIMAGE="$(find . -type f -name bzImage)"

mv "$TEMP_DIR/$KERNEL_RELPATH/$BZIMAGE" /bzImage
mv "$TEMP_DIR/$KERNEL_RELPATH/vmlinux" /vmlinux
mv "$TEMP_DIR/$KERNEL_RELPATH/System.map" /System.map

make clean

mv /bzImage "$TEMP_DIR/$KERNEL_RELPATH/$BZIMAGE"
mv /vmlinux "$TEMP_DIR/$KERNEL_RELPATH/vmlinux"
mv /System.map "$TEMP_DIR/$KERNEL_RELPATH/System.map"
)
rsync -ra "${TEMP_DIR}/" "$SNAPCHANGE_BUILT_TARGET"