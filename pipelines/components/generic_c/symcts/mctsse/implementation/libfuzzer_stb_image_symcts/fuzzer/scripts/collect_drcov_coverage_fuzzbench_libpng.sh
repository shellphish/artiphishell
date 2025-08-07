#!/bin/bash

export DRHOME=/home/honululu/lukas/tools/DynamoRIO-Linux-8.0.0-1/bin64

function collect_coverage_single() {
    # set -x
    INPUT=$1
    OUTDIR=$2
    mkdir -p "$OUTDIR"
    $DRHOME/drrun -t drcov -logdir "$OUTDIR" -- ./local_fuzzbench_testing/target-afl-vanilla "$INPUT" 1>/dev/null 2>/dev/null
    # set +x
}

function collect_coverage() {
    INDIR=$1
    OUTDIR=$2
    mkdir -p "$2"
    for f in `find $1 \( ! -regex '.*/\.[^/]*' \) | sort`; do
        echo "Processing $f ..."
        collect_coverage_single "$f" "$OUTDIR"
    done
}

rm -rf ./cov_drcov/symcts_latest
collect_coverage ./sync/symcts_latest/corpus ./cov_drcov/symcts_latest
collect_coverage ./sync/symcts_latest/crashes ./cov_drcov/symcts_latest


