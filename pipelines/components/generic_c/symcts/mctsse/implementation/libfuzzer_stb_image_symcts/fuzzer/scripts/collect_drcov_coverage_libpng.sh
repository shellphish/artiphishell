#!/bin/bash

export DRHOME=/home/honululu/lukas/tools/DynamoRIO-Linux-8.0.0-1/bin64

function collect_coverage_single() {
    # set -x
    INPUT=$1
    OUTDIR=$2
    mkdir -p "$OUTDIR"
    $DRHOME/drrun -t drcov -logdir "$OUTDIR" -- ./libpng_read_fuzzer "$INPUT"
    # set +x
}

function collect_coverage() {
    INDIR=$1
    OUTDIR=$2
    mkdir -p "$2"
    for f in `find $1 | grep -v .lafl_lock | grep -v 'queue/.state/' | sort`; do
        echo "Processing $f ..."
        collect_coverage_single "$f" "$OUTDIR"
    done
}

# collect_coverage ./corpus_oss_fuzz/libpng/libpng_read_fuzzer ./cov_drcov_libpng/oss_fuzz
collect_coverage /tmp/symcts_corpus/symcts/corpus/ ./cov_drcov_libpng/symcts_1h
collect_coverage /tmp/symcts_afl_corpus/symcts/corpus/ ./cov_drcov_libpng/symcts_afl_1h