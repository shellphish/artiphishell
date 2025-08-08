#!/usr/bin/bash
set -x
set -e

export TARGET_DIR=${TARGET_DIR}
export TARGET_ID=${TARGET_ID}
export CP_HARNESS_ID=${CP_HARNESS_ID}
export CP_HARNESS_NAME=${CP_HARNESS_NAME}
export DOCKER_IMAGE_NAME=${DOCKER_IMAGE_NAME}

. /shellphish/aflpp/setup_cp_name.sh

export INSTANCE_DIR="/shared/aflpp/fuzz/main-${TARGET_ID}-${CP_NAME}-${JOB_ID}"
mkdir -p "$INSTANCE_DIR"
cp ${TARGET_DIR}/out/"${CP_HARNESS_NAME}" ${TARGET_DIR}/out/"${CP_HARNESS_NAME}.original"
rsync -raz ${TARGET_DIR}/ ${INSTANCE_DIR}/

/shellphish/aflpp/run_fuzzer_instance_in_background.sh main -t 1000

/shellphish/aflpp/main_node_rsync_shit.sh