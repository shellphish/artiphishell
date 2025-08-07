#!/bin/bash
set -x
while (( $# >= 1)); do
    case $1 in
    --database-dir) DATABASE_DIR=$2; shift; shift;;
    --results-dir) RESULTS_DIR=$2; shift; shift;;
    *) break;
    esac;
done
cd java-sanitizer-queries

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

codeql pack install
cd -

YQ=/shellphish/yq_linux_amd64
QLPACK_NAME=$("$YQ" -r ".name" java-sanitizer-queries/qlpack.yml)
NPROC=${NPROC_VAL:-$(nproc)}
codeql database run-queries --threads=$NPROC --common-caches=/work/.codeql "$DATABASE_DIR" java-sanitizer-queries/
CODEQL_RESULTS_DIR="$DATABASE_DIR/results/$QLPACK_NAME/"
