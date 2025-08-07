#!/bin/bash

export DRHOME=/home/honululu/lukas/tools/DynamoRIO-Linux-8.0.0-1/bin64

function collect_coverage_single() {
    # set -x
    INPUT=$1
    OUTDIR=$2
    mkdir -p "$OUTDIR"
    timeout 10 $DRHOME/drrun -t drcov -logdir "$OUTDIR" -- ./harness_symcc_coverage "$INPUT" 1>/dev/null 2>/dev/null
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

COV_DIR=./cov_drcov_stb

collect_coverage ./corpus_oss_fuzz/stb/stbi_read_fuzzer $COV_DIR/oss_fuzz_saturated

# collect_coverage ./local_experiment_new_coverage_1w_cmplog/minimized_union_corpus/afl/corpus $COV_DIR/cmplog_afl
# collect_coverage ./local_experiment_new_coverage_1w_cmplog/minimized_union_corpus/afl/crashes $COV_DIR/cmplog_afl
# collect_coverage ./local_experiment_new_coverage_1w_cmplog/minimized_union_corpus/symcc_afl/corpus $COV_DIR/cmplog_symcc_afl
# collect_coverage ./local_experiment_new_coverage_1w_cmplog/minimized_union_corpus/symcc_afl/crashes $COV_DIR/cmplog_symcc_afl
# collect_coverage ./local_experiment_new_coverage_1w_cmplog/minimized_union_corpus/symcts/corpus $COV_DIR/cmplog_symcts
# collect_coverage ./local_experiment_new_coverage_1w_cmplog/minimized_union_corpus/symcts/crashes $COV_DIR/cmplog_symcts
# collect_coverage ./local_experiment_new_coverage_1w_cmplog/minimized_union_corpus/symcts_afl/corpus $COV_DIR/cmplog_symcts_afl
# collect_coverage ./local_experiment_new_coverage_1w_cmplog/minimized_union_corpus/symcts_afl/crashes $COV_DIR/cmplog_symcts_afl

# collect_coverage ./local_experiment_new_coverage_1w_cmplog/union_symcts/ $COV_DIR/cmplog_symcts
# collect_coverage ./local_experiment_new_coverage_1w_cmplog/union_symcts_afl/ $COV_DIR/cmplog_symcts_afl
# collect_coverage ./local_experiment_new_coverage_1w_cmplog/union_symcc_afl/ $COV_DIR/cmplog_symcc_afl

#rm -rf ./cov_drcov_stb/symcts_1699153
#collect_coverage ./sync/symcts_1699153/queue $COV_DIR/symcts_latest
#collect_coverage ./sync/symcts_1699153/crashes $COV_DIR/symcts_latest

