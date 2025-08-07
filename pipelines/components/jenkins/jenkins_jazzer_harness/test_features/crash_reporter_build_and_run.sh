#!/usr/bin/bash

set -e
set -x

pushd ./fuzz_jenkins
pdl --unlock || rm -rf pipeline.lock
pdl
pd inject jazzer_crash_report.target_with_sources 1 < ./aixcc-sc-challenge-002-jenkins-cp.tar.gz
cat <<EOF | pd inject jazzer_crash_report.crash_meta 222
target_id: "1"
harness_id: "222"
cp_harness_id: "id_1"
EOF
echo "eC1ldmlsLWJhY2tkb29yAGJyZWFraW4gdGhlIGxhdwBqYXp6ZQ==" | base64 -d | pd inject jazzer_crash_report.crashing_input 222

ipython --pdb -- "$(which pd)" run --verbose --debug-trace
pd status
popd
