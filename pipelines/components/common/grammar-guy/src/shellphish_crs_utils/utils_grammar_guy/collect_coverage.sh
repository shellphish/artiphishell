#!/bin/bash

set -e #ux 

export BINARY_PATH="/$1"
export GENERATED_INPUTS='/work/inputs/'
export RUNS=$(ls -1 ${GENERATED_INPUTS} | wc -l)
export GENERATED_COVERAGE="/work/coverage/"
 
cd /out
echo "SCR: Collecting coverage on ${BINARY_PATH} in ${RUNS} runs";

mkdir -p $GENERATED_COVERAGE

# Renaming all files to test_%d.json for later zurordnbarkeit
i=0
for file in $(ls -p ${GENERATED_INPUTS} | grep -v /); do
    inputfile=$(printf "test_%d.json" $i)
    mv "${GENERATED_INPUTS}/${file}" "${GENERATED_INPUTS}/${inputfile}"
    ASAN_OPTIONS=detect_leaks=0 LLVM_PROFILE_FILE="${GENERATED_COVERAGE}/spearfuzz_coverage$i.profraw" "${BINARY_PATH}" "${GENERATED_INPUTS}/${inputfile}"
    i=$((i+1))
done

# echo "Merging coverage information"
# Collect all the profraw files in the coverage directory and add to "target_mergelist.txt"
echo "SCR: IN collect coverage MERGELIST AT ${GENERATED_COVERAGE}spearfuzz_mergelist.txt"

if [ ! -f "${GENERATED_COVERAGE}spearfuzz_mergelist.txt" ]; then
    touch "${GENERATED_COVERAGE}spearfuzz_mergelist.txt"
fi

pushd "${GENERATED_COVERAGE}"
# Do for each file separately
mkdir -p "${GENERATED_COVERAGE}/profdata"
for filename in *.profraw;do
    if [ -f "$filename" ]; then
        echo "${filename}" >> "${GENERATED_COVERAGE}spearfuzz_mergelist.txt"
        # create profdata file for each entry in the folder
        llvm-profdata merge -sparse "${filename}" -o "${GENERATED_COVERAGE}/profdata/${filename}.profdata"
    else
        echo "SRC: NO COVERAGE FILES FOUND IN ${GENERATED_COVERAGE}/profdata/${filename}. ABORT"
        exit 1
    fi
done
popd

pushd "${GENERATED_COVERAGE}"
llvm-profdata merge -sparse --input-files="${GENERATED_COVERAGE}spearfuzz_mergelist.txt" --output="${GENERATED_COVERAGE}spearfuzz.profdata"
popd

