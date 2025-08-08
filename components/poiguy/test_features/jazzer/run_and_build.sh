#!/bin/bash

set -e
set -x

docker build ../../ --tag="aixcc-poi-guy"

pdl --unlock || rm -f ./pipeline.lock
pdl

pd inject poiguy_jazzer.jazzer_crash_report 222 < crash_report.json
pd inject poiguy_jazzer.jazzer_crash_reports_metadata 222 < crash_report_metadata.yaml
pd inject poiguy_jazzer.jazzer_index_csv_path 1 < index.csv

pd --verbose --debug-trace run
pd status

if [ $(pd ls poiguy_jazzer.poi_reports | wc -l) -eq 1 ]; then
    echo 'SUCCESS'
    exit 0
else
    echo 'FAILED'
    exit -1
fi
 
