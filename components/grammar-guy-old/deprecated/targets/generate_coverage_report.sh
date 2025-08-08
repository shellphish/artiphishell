#!/bin/bash
#
# TODO add format options

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <target>"
    exit 1
fi

export COVERAGEDIR="$(realpath ../work/outputs/coverage)"
export TARGET=$1

export BINNAME=""

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

export BINDIR="$(realpath targets-semis-${TARGET}/out)"
export SRCDIR="$(realpath targets-semis-${TARGET}/src)"

llvm-cov-14 show -format=text -o "${COVERAGEDIR}/${TARGET}/${TARGET}_cov.txt" -path-equivalence="/cp-src/,${SRCDIR}" -instr-profile="${COVERAGEDIR}/${TARGET}/${TARGET}_fuzz.profdata" "${BINDIR}/${BINNAME}"
llvm-cov-14 export -format=text -instr-profile="${COVERAGEDIR}/${TARGET}/${TARGET}_fuzz.profdata" "${BINDIR}/${BINNAME}" > "${COVERAGEDIR}/${TARGET}/${TARGET}_cov.json"
llvm-cov-14 show -format=html -o "${COVERAGEDIR}/${TARGET}/${TARGET}_cov.html" -path-equivalence="/cp-src/,${SRCDIR}" -instr-profile="${COVERAGEDIR}/${TARGET}/${TARGET}_fuzz.profdata" "${BINDIR}/${BINNAME}"