#!/bin/bash
#

if [ "$#" -ne 1 ]; then
    echo "Usage: $0"
    exit 1
fi
GRAMMAR_PATH="$1"
INPUT_PATH="$2"
COVERAGE_PATH="$3"
ALLOWLIST_PATH="$4"

# pushd "${GG_ROOT}"
# clean coverage folder
rm -rf "${GRAMMAR_PATH}"
mkdir -p "${GRAMMAR_PATH}"

# clean generated inputs and generators
rm -rf "${INPUT_PATH}/*.json"
rm -rf "${INPUT_PATH}/generators/*"

# clean coverage information and reports
rm -rf "${COVERAGE_PATH}"
mkdir "${COVERAGE_PATH}"

# clean allowlist+
rm -rf "${ALLOWLIST_PATH}/allowlist.txt"
# popd