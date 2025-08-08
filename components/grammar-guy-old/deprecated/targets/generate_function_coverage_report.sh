#!/bin/bash
#
# TODO add format options

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <target>"
    exit 1
fi

echo "Creating coverage report for target: $1";
export COVERAGEDIR="$(realpath ../work/outputs/coverage)"
export TARGET=$1
export ITERATION=$2

export BINNAME=""

# This just assigns the correct binary name for the given target. There can be multiple binaries for one target. Depending on the harnessing situation
case ${1} in
"clib" )
    export BINNAME="fuzz_manifest"
;;
"cjson" )
    export BINNAME="cjson_read_fuzzer"
;;
"jq-execute" )
    export TARGET="jq"
    export BINNAME="jq_fuzz_execute"
;;
"jq-compile" )
    export TARGET="jq"
    export BINNAME="jq_fuzz_compile"
;;
"jq-parse" )
    export TARGET="jq"
    export BINNAME="jq_fuzz_parse"
;;
esac

if [ ! -d "${COVERAGEDIR}/${TARGET}/${ITERATION}" ]; then
    mkdir -p "${COVERAGEDIR}/${TARGET}/${ITERATION}"
fi

export BINDIR="$(realpath targets-semis-${TARGET}/out)"
export SRCDIR="$(realpath targets-semis-${TARGET}/src)"

llvm-cov-14 show -format=text -name-allowlist="${COVERAGEDIR}/${TARGET}_allowlist.txt" -use-color=0 -output-dir "${COVERAGEDIR}/${TARGET}/${ITERATION}" -path-equivalence="/cp-src/,${SRCDIR}" -instr-profile="${COVERAGEDIR}/${TARGET}/${TARGET}_fuzz.profdata" "${BINDIR}/${BINNAME}"
llvm-cov-14 show -format=html -o "${COVERAGEDIR}/${TARGET}/${ITERATION}/${TARGET}_report" -path-equivalence="/cp-src/,${SRCDIR}" -instr-profile="${COVERAGEDIR}/${TARGET}/${TARGET}_fuzz.profdata" "${BINDIR}/${BINNAME}"