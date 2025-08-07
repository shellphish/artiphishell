#!/bin/bash

# This task is responsible for running the codeql ql packs
# see: https://docs.github.com/en/code-security/codeql-cli/getting-started-with-the-codeql-cli/analyzing-your-code-with-codeql-queries#running-codeql-database-analyze
# analyze_database.sh takes the following arguments:
# --database-dir: The path to the directory where the database is located (at <path>/db)
# --report-dir: The path to the directory where the report should be created (at <path>/report.csv)
# --format: The format of the report (csv or sarif)

# NOTES:
#   - <path>/db must exist when running this script
#   - it is possible to change the output format to something other than csv (e.g., sarif)
#   - it is possible to run more/different queries. Currently we only run the standard queries for code scanning
#   - the script is configured to use as many threads as the logical cores on the machine
set -x

while (( $# >= 1 )); do
    case $1 in
    --extraction-request) EXTRACTION_REQUEST_JSON=$2; shift; shift;;
    --database-dir) DATABASE_DIR=$2; shift; shift;;
    --results-dir) RESULTS_DIR=$2; shift; shift;;
    --language) LANGUAGE=$2; shift; shift;;
    *) break;
    esac;
done


mkdir -p info-extraction-ql-pack/
python3 specialize-info-extraction.py "$LANGUAGE" "$EXTRACTION_REQUEST_JSON"

cd info-extraction-ql-pack/

# check that all files in this directory must end either in .unused, .yml, .yaml, .ql or .qll
for file in *; do
    if [[ ! -f "$file" ]]; then
        continue
    fi
    if [[ ! "$file" =~ \.(yml|yaml|ql|qll|unused)$ ]]; then
        echo "Error: $file does not end in .unused, .yml, .yaml, .ql or .qll"
        exit 1
    fi
done
# ls -al ./
codeql pack install
cd -

YQ=/shellphish/yq_linux_amd64
QLPACK_NAME=$("$YQ" -r ".name" info-extraction-ql-pack/codeql-pack.yml)
NPROC=${NPROC_VAL:-$(nproc)}
codeql database run-queries --threads=$NPROC --common-caches=/work/.codeql "$DATABASE_DIR" info-extraction-ql-pack/
CODEQL_RESULTS_DIR="$DATABASE_DIR/results/$QLPACK_NAME/"

rsync -ra "$CODEQL_RESULTS_DIR"/ "$RESULTS_DIR"/

# codeql bqrs decode --format=json -o "$REPORT_DIR/kernel_reaching_syscalls.json"     "$RESULTS_DIR/kernel_reaching_syscalls.bqrs"
# codeql bqrs decode --format=json -o "$REPORT_DIR/kernel_reaching_files.json"        "$RESULTS_DIR/kernel_reaching_files.bqrs"
# codeql bqrs decode --format=json -o "$REPORT_DIR/cpp_find_vars_and_fields.json"     "$RESULTS_DIR/cpp_find_vars_and_fields.bqrs"
# codeql bqrs decode --format=json -o "$REPORT_DIR/cpp_generic_find_enum_usages.json" "$RESULTS_DIR/cpp_generic_find_enum_usages.bqrs"

# python /shellphish/merge_jsons.py "$REPORT_DIR/extracted-info.json" "$REPORT_DIR"/*.json
