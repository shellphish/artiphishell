#!/bin/bash

set -x
HARNESS_NAME=$1
FUZZ_CONFIG=$2
AFL_UPSTREAM_TARGET=$3
AFL_UPSTREAM_CMPLOG_TARGET=$4
AFL_COV_TARGET=$5
SYMCC_TARGET=$6
FOUND_SEEDS_DIR=$7
FOUND_CRASHES_DIR=$8
shift 8
ARGS="$@"
# MCTSSE_DIR=/home/honululu/lukas/research/mctsse
MCTSSE_DIR=/mctsse

DICT_PATH=$(dirname "$AFL_COV_TARGET")/dict.txt
DICT_OPTION=""
if [ -f "$DICT_PATH" ]; then
    DICT_OPTION="-x $DICT_PATH"
fi

PROJECT_DIR=$(dirname $(dirname "${AFL_UPSTREAM_TARGET}"))
PROJECT_NAME=$(yq -r ".cp_name" "$PROJECT_DIR/project.yaml")

OUT_DIR="/shared/symcts_fuzz/${PROJECT_NAME}_${HARNESS_NAME}"

# if the OUT_DIR already exists, tar it into a backup and delete it
if [ -d "$OUT_DIR" ]; then
    echo "Backing up existing OUT_DIR"
    # get last modified time of the OUT_DIR, suffix the tar with it
    LAST_MODIFIED=$(stat -c %Y $OUT_DIR)
    tar -czf ${OUT_DIR}_${LAST_MODIFIED}.tar.gz $OUT_DIR
    rm -rf $OUT_DIR
fi
LOG_DIR=$OUT_DIR/logs
mkdir -p $LOG_DIR

chmod +x $AFL_UPSTREAM_TARGET
chmod +x $AFL_COV_TARGET
chmod +x $SYMCC_TARGET

# for libSymRuntime
export LD_LIBRARY_PATH=$MCTSSE_DIR/implementation/libfuzzer_stb_image_symcts/runtime/target/release/:$LD_LIBRARY_PATH

# Prepare the corpus
CORPUS_DIR="${CORPUS_DIR:-$OUT_DIR/corpus}"
mkdir -p $CORPUS_DIR

if [ -f ${AFL_COV_TARGET}_seed_corpus.zip ]; then
    echo "Found seed corpus, extracting"
    unzip -o ${AFL_COV_TARGET}_seed_corpus.zip -d $CORPUS_DIR
    ls -l $CORPUS_DIR
fi

# if no files are in the corpus, create one
if [ -z "$(ls -A $CORPUS_DIR)" ]; then
    echo "No corpus found, loading the best seed in the world"
    echo 'fuzz' > $CORPUS_DIR/fuzzfuzz
fi
SYNC_DIR="${SYNC_DIR:-$OUT_DIR/sync}"
mkdir -p $SYNC_DIR

# function to spawn the broker
function broker() {
    # for now, the first instance canonically just acts as the broker, replace with dedicated broker later
    symcts \
        --afl-coverage-target $AFL_COV_TARGET \
        --symcc-target $SYMCC_TARGET \
        --concolic-execution-mode symcc \
        -n 'symcts_0_broker' \
        -i $CORPUS_DIR \
        -s $SYNC_DIR \
        -- > $LOG_DIR/symcts_0_broker.log 2>&1
}

function fuzz_symcts() {
    NAME=$1
    LOG_OUT_FILE=$LOG_DIR/$NAME.log
    symcts \
        --afl-coverage-target $AFL_COV_TARGET \
        --symcc-target $SYMCC_TARGET \
        --concolic-execution-mode symcc \
        -n "$NAME" \
        -i $CORPUS_DIR \
        -s $SYNC_DIR \
        -- > $LOG_OUT_FILE 2>&1
}
function fuzz_afl() {
    NAME=$1
    TARGET=$AFL_UPSTREAM_TARGET
    MODE="-S $NAME"
    CMPLOG_FLAG=""
    if [ "$NAME" == "aflpp_1" ]; then
        NAME="${NAME}_main"
        MODE="-M ${NAME}"
    elif [ "$NAME" == "aflpp_2" ] || [ "$NAME" == "aflpp_3" ]; then
        NAME="${NAME}_cmplog"
        CMPLOG_FLAG="-c $AFL_UPSTREAM_CMPLOG_TARGET"
        MODE="-S ${NAME}"
    fi
    LOG_OUT_FILE=$LOG_DIR/$NAME.log


    export AFL_DEBUG=1
    export AFL_FAST_CAL=1
    export AFL_DISABLE_TRIM=1
    /inst/AFLplusplus_upstream/afl-fuzz \
        -i $CORPUS_DIR \
        -o $SYNC_DIR \
        $DICT_OPTION \
        $MODE \
        $CMPLOG_FLAG \
        "$AFL_UPSTREAM_TARGET" \
        -- - > $LOG_OUT_FILE 2>&1
}

broker &
sleep 1

N_INSTANCES_TOTAL=$(yq ".cores_per_harness.$HARNESS_NAME" $FUZZ_CONFIG)
N_INSTANCES_SYMCTS=$((N_INSTANCES_TOTAL / 2))
N_INSTANCES_AFLPP=$((N_INSTANCES_TOTAL / 2))

for i in $(seq 1 $N_INSTANCES_SYMCTS); do
    fuzz_symcts "symcts_$i" &
    sleep 1
done

for i in $(seq 1 $N_INSTANCES_AFLPP); do
    fuzz_afl "aflpp_$i" &
    sleep 1
done


# python3 /sync_inputs_inotify.py $SYNC_DIR $FOUND_SEEDS_DIR $FOUND_CRASHES_DIR || \
#     python3 /sync_inputs_polling.py $SYNC_DIR $FOUND_SEEDS_DIR $FOUND_CRASHES_DIR
/sync_inputs.sh $OUT_DIR/ $SYNC_DIR $FOUND_SEEDS_DIR $FOUND_CRASHES_DIR