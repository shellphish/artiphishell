#!/bin/bash

set -x
set -e

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
cd "$SCRIPT_DIR"

pdl --unlock || rm -rf pipeline.lock

(
    pushd ../../
    docker buildx build -t aixcc-codeql . --load
    popd
)
pdl

if [ ! -f aixcc-sc-challenge-002-jenkins-cp.tar.gz ]; then
    git clone https://github.com/shellphish-support-syndicate/aixcc-sc-challenge-002-jenkins-cp/
    pushd aixcc-sc-challenge-002-jenkins-cp
    ./run.sh pull_source
    tar -cvzf ../aixcc-sc-challenge-002-jenkins-cp.tar.gz .
    popd
    rm -rf ./aixcc-sc-challenge-002-jenkins-cp
fi

pd inject codeql_create_db.target_with_sources 1 < aixcc-sc-challenge-002-jenkins-cp.tar.gz
pd inject codeql_run_info_extraction.info_extraction_request 666 < reachability-request.yaml

pd --verbose --debug-trace run

