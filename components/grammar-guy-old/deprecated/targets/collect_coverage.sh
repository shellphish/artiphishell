#!/bin/bash

# MAKE THIS GENERIC & separate merge and show
# Split coverage & input
# Script to zip coverage && Merge + report
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <number_of_runs> <target_name>"
    exit 1
fi

set -e #ux 

echo "Collecting coverage for $1 runs on $2";
export COVERAGEDIR="$(realpath ../work/outputs/coverage)"
export RUNS=$1
export TARGET=$2
export INPUT="$(realpath ../work/inputs)"

export runs=$(($RUNS - 1))

echo "Running coverage collection"

export BINNAME=$2
case $2 in

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

export OUTPUTDIR="$(realpath ../work/inputs/${TARGET})"
export BINDIR=$(realpath targets-semis-${TARGET}/out)

mkdir -p "${COVERAGEDIR}/${TARGET}"

i=0
for file in $(ls -p ${OUTPUTDIR} | grep -v /); do
    inputfile=$(printf "test_%d.json" $i)
    mv "${OUTPUTDIR}/${file}" "${OUTPUTDIR}/${inputfile}"
    
ASAN_OPTIONS=detect_leaks=0 LLVM_PROFILE_FILE="${COVERAGEDIR}/${TARGET}/${TARGET}_coverage$i.profraw" "${BINDIR}/${BINNAME}" "${INPUT}/${TARGET}/${inputfile}"
i=$((i+1))
done

# echo "Merging coverage information"

# Collect all the profraw files in the coverage directory and add to "target_mergelist.txt"

if [ ! -f "${COVERAGEDIR}/${TARGET}/${TARGET}_mergelist.txt" ]; then
# echo "creating mergelists at ${COVERAGEDIR}/${TARGET}/${TARGET}_mergelist.txt"
    touch "${COVERAGEDIR}/${TARGET}/${TARGET}_mergelist.txt"
fi

for filename in "${COVERAGEDIR}/${TARGET}"/*.profraw;do
    echo "${filename}" >> "${COVERAGEDIR}/${TARGET}/${TARGET}_mergelist.txt"
done

llvm-profdata-14 merge -sparse --input-files="${COVERAGEDIR}/${TARGET}/${TARGET}_mergelist.txt" --output="${COVERAGEDIR}/${TARGET}/${TARGET}_fuzz.profdata"
