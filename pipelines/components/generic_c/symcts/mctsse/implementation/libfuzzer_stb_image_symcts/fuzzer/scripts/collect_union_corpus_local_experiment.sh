#!/bin/bash

set -eu
# set -x

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

TARGET_DIR=$1

function collect_union_corpus() {
    NAME=$1
    GLOB_PATTERN=$2

    echo "Collecting union corpus for $NAME"

    # expand glob pattern into an array
    GLOB_ARRAY=($(eval echo $GLOB_PATTERN))

    mkdir -p "$TARGET_DIR/$NAME"

    # run on each element of the GLOB_ARRAY in parallel, call "$SCRIPT_DIR/copy_testcases.sh <element> <target_dir>"
    parallel --jobs 8 "$SCRIPT_DIR/copy_corpus_testcases.sh {} $TARGET_DIR/$NAME" ::: "${GLOB_ARRAY[@]}"

    echo "Collected $(ls $TARGET_DIR/$NAME | wc -l) files"
}

collect_union_corpus "union_corpus_afl" '$TARGET_DIR/local_experiment_sync_afl_[1-5]/'
collect_union_corpus "union_corpus_symcc_afl" '$TARGET_DIR/local_experiment_sync_symcc_afl_[1-5]/'
collect_union_corpus "union_corpus_symcts" '$TARGET_DIR/local_experiment_sync_symcts_[1-5]/'
collect_union_corpus "union_corpus_symcts_afl" '$TARGET_DIR/local_experiment_sync_symcts_afl_[1-5]/'

