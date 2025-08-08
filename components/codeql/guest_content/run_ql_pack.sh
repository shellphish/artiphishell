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

while (( $# >= 1 )); do
    case $1 in
    --database-dir) DATABASE_DIR=$2; shift; shift;;
    --report-dir) REPORT_DIR=$2; shift; shift;;
    --format) FORMAT=$2; shift; shift;;
    --target) TARGET=$2; shift; shift;;
    *) break;
    esac;
done

NPROC=${NPROC_VAL:-$(nproc)}

# if target is Linux
if [ "$TARGET" = "Linux" ]; then
    cd /scripts/unix/jenkins-ql-pack/src && codeql pack install
    codeql database analyze --threads=$NPROC --format=$FORMAT --output=$REPORT_DIR/report.sarif --common-caches=/work/.codeql $DATABASE_DIR/ /scripts/unix/kernel-ql-pack/src
elif [ "$TARGET" = "jenkins" ]; then
    cd /scripts/unix/jenkins-ql-pack/src && codeql pack install
    codeql database analyze --threads=$NPROC --format=$FORMAT --output=$REPORT_DIR/report.sarif --common-caches=/work/.codeql $DATABASE_DIR/ /scripts/unix/jenkins-ql-pack/src
else
    echo "Unknown target"
fi
