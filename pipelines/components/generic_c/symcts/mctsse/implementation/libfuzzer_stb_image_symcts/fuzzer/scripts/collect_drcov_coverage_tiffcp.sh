#!/bin/bash

export DRHOME=/home/honululu/lukas/tools/DynamoRIO-Linux-8.0.0-1/bin64

function collect_coverage_single() {
    # set -x
    INPUT="$1"
    OUTDIR="$2"
    mkdir -p "$OUTDIR"

    # get mktemp path for /tmp/cov_input_tiffcp_$(date +%s)
    TEMPLATE=/tmp/.cov_input_tiffcp_$(date +%s).XXXXXX
    TMPPATH=$(mktemp -u $TEMPLATE)
    ln -s "$INPUT" "$TMPPATH"
    $DRHOME/drrun -t drcov -logdir "$OUTDIR" -- ./tiffcp -M "$TMPPATH" /tmp/tiffcp.out >/dev/null 2>/dev/null
    rm -f "$TMPPATH"
    # set +x
}

function collect_coverage() {
    INDIR="$1"
    OUTDIR="$2"
    mkdir -p "$2"
    for f in $(find $1 | grep -v .lafl_lock | grep -v 'hangs' | grep -v 'queue/.state/' | sort); do
        echo "Processing $f ..."
        collect_coverage_single "$f" "$OUTDIR"
    done
}

# collect_coverage ./corpus_oss_fuzz/libtiff/tiff_read_rgba_fuzzer ./cov_drcov_libtiff/oss_fuzz
# collect_coverage ~/lukas/research/mctsse/repos/magma/tools/captain/workdir_14d/ar/symcts/libtiff/tiffcp/0/ball/findings/afl-master ./cov_drcov_libtiff/symcts_5d_0/
# collect_coverage ~/lukas/research/mctsse/repos/magma/tools/captain/workdir_14d/ar/symcts/libtiff/libtiff_read_fuzzer/1/ball/findings/afl-master ./cov_drcov_libtiff/symcts_5d_1/

# collect_coverage ~/lukas/research/mctsse/repos/magma/tools/captain/workdir_14d/ar/aflplusplus/libtiff/tiffcp/0/ball/findings/ ./cov_drcov_libtiff/aflplusplus_5d_0/
# collect_coverage ~/lukas/research/mctsse/repos/magma/tools/captain/workdir_14d/ar/aflplusplus/libtiff/libtiff_read_fuzzer/1/ball/findings/ ./cov_drcov_libtiff/aflplusplus_5d_1/

collect_coverage ./sync/symcts_692719/ ./cov_drcov_libtiff/symcts_libtiff/