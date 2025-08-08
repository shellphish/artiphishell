#!/bin/bash

set -e
cd ci_tests/
docker build .. --tag="aixcc-poi-guy"

cp ../pipeline.yml .

pdl
pd restore ./inject/finished/backup/
pd --verbose run

output=$(pd cat poiguy_codeql.codeql_report_dir 1)

# Check if the output is 12
if [ "$output" -eq 12 ]; then
    echo "Output is 12, exiting with status 0"
    exit 0
else
    echo "Output is not 12, exiting with status 1"
    exit 1
fi
