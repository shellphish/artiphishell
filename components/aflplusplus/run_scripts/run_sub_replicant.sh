#!/usr/bin/bash
set -e
set -x

export CMPLOG_TARGET_DIR=${CMPLOG_TARGET_DIR}
export TARGET_DIR=${TARGET_DIR}
export TARGET_ID=${TARGET_ID}
export CP_HARNESS_ID=${CP_HARNESS_ID}
export CP_HARNESS_NAME=${CP_HARNESS_NAME}
export CP_HARNESS_BINARY_PATH=${CP_HARNESS_BINARY_PATH}
export DOCKER_IMAGE_NAME=${DOCKER_IMAGE_NAME}


. /shellphish/aflpp/setup_cp_name.sh

export INSTANCE_DIR="/shared/aflpp/fuzz/multi-${TARGET_ID}-${CP_NAME}-${JOB_ID}-${REPLICA_ID}"
mkdir -p "$INSTANCE_DIR"
cp ${TARGET_DIR}/out/"${CP_HARNESS_NAME}" ${TARGET_DIR}/out/"${CP_HARNESS_NAME}.original"
rsync -raz ${TARGET_DIR}/ ${INSTANCE_DIR}/

fuzz() {
set -- "$@"
. /shellphish/aflpp/run_fuzzer_instance_in_background.sh
}

export RAND_MIN=0
export RAND_MAX=8
export RAND_NUM=$(( RAND_MIN + ( $(od -An -N2 -tu2 /dev/urandom) % (RAND_MAX - RAND_MIN + 1) ) ))

case $RAND_NUM in
0)
    fuzz ${JOB_ID}_${REPLICA_ID}_0_cmplog -t 1000 -c "/$CP_HARNESS_BINARY_PATH.cmplog"
    ;;
1)
    fuzz ${JOB_ID}_${REPLICA_ID}_1_afldict -t 1000 -x /work/dictionary.txt
    ;;
2)
    fuzz ${JOB_ID}_${REPLICA_ID}_2 -t 500
    ;;
3)
    fuzz ${JOB_ID}_${REPLICA_ID}_3 -t 500
    ;;
4)
    fuzz ${JOB_ID}_${REPLICA_ID}_4 -t 1000
    ;;
5)
    fuzz ${JOB_ID}_${REPLICA_ID}_5 -t 1000
    ;;
6)
    fuzz ${JOB_ID}_${REPLICA_ID}_6 -t 2000
    ;;
7)
    fuzz ${JOB_ID}_${REPLICA_ID}_7 -t 5000
    ;;
esac

wait -n