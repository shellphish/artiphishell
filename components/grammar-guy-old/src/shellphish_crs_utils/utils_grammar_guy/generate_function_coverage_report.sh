#!/bin/bash
#
# TODO add format options

set -eux

export COVERAGE_PATH="/work/coverage/"
export ITERATION="$1"
export ALLOWLIST_PATH="/work/allowlist.txt"
export TARGET_PATH="/src/"
export BINARY_PATH="/$2"

echo "SCR: COVERAGE_PATH: $COVERAGE_PATH"
echo "SCR: ITERATION: $ITERATION"
echo "SCR: ALLOWLIST_PATH: $ALLOWLIST_PATH"
echo "SCR: TARGET_PATH: $TARGET_PATH"
echo "SCR: BINARY_PATH: $BINARY_PATH"

# This just assigns the correct binary name for the given target. There can be multiple binaries for one target. Depending on the harnessing situation
echo "SCR: Coverage report of coverage at "${COVERAGE_PATH}/${ITERATION}""
mkdir -p "${COVERAGE_PATH}/${ITERATION}"

echo "SCR: Creating coverage report for all the files separately" 
# Create a coverage report for each of the profdata files except the spearfuzz.profdata in the coverage_path. Name it after the profraw files name

llvm-cov show -format=text -use-color=0 -o "${COVERAGE_PATH}/${ITERATION}" -path-equivalence="/,/work/compilation_cache/" -instr-profile="${COVERAGE_PATH}/spearfuzz.profdata" "${BINARY_PATH}"
# llvm-cov export -format=lcov -use-color=0 -path-equivalence="/,/work/compilation_cache/" -instr-profile="${COVERAGE_PATH}/spearfuzz.profdata" "${BINARY_PATH}" > "${COVERAGE_PATH}/spearfuzz_report"
# llvm-cov show -format=html -o "${COVERAGE_PATH}/${ITERATION}/spearfuzz_report" -path-equivalence="/,/work/compilation_cache/" -instr-profile="${COVERAGE_PATH}/spearfuzz.profdata" "${BINARY_PATH}"

# Iterate over all .profdata files in the folder and generate the hmtl coverage report.
# FOR SEPARATE REPORT GENERATION
# pushd "${COVERAGE_PATH}/profdata"
# for filename in *.profdata; do
#     echo "SCR: Creating coverage report for ${filename}"
#     llvm-cov show -format=text -name-allowlist=${ALLOWLIST_PATH} -use-color=0 -o "${COVERAGE_PATH}/${ITERATION}/${filename}_textreport" -path-equivalence="/,/work/compilation_cache/" -instr-profile="${filename}" "${BINARY_PATH}"
#     llvm-cov show -format=html -o "${COVERAGE_PATH}/${ITERATION}/${filename}_htmlreport" -path-equivalence="/,/work/compilation_cache/" -instr-profile="${filename}" "${BINARY_PATH}"
# done
# popd

# llvm-cov show -format=text -use-color=0 -o "${COVERAGE_PATH}/${ITERATION}" -path-equivalence="/,/work/compilation_cache/" -instr-profile="${COVERAGE_PATH}/spearfuzz.profdata" "${BINARY_PATH}"