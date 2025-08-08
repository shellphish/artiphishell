#!/bin/bash

# NOTES:
#
#  1- When this test is running in the worker,
#     the working directory is the directory of the component being tested (
#     so <artiphishell_root>/components/<component_name>)
#
#  2- You are in charge of building your own container.
#
#  3- The worker:
#      - Can read/clone any repo under github.com/shellphish-support-syndicate
#      - Can docker pull any images from ghcr.io/shellphish-support-syndicate
#

set -x
set -e

sudo rm -rf /shared/

# Building my own container with the latest code.
docker build -t aixcc-invariantguy .

# In this folder we have also the artifact from the tests-data rep
cd ./ci_tests/c-testing-nginx/

pdl --ignore-required

# if the folder exists, wipe it
if [ -d targets-semis-aixcc-sc-challenge-004-full-nginx-cp ]; then
    rm -rf targets-semis-aixcc-sc-challenge-004-full-nginx-cp
    # also wipe the tar
    rm -f targets-semis-aixcc-sc-challenge-004-full-nginx-cp.tar.gz
fi

git clone https://github.com/shellphish-support-syndicate/targets-semis-aixcc-sc-challenge-004-full-nginx-cp.git

pushd targets-semis-aixcc-sc-challenge-004-full-nginx-cp
make cpsrc-prepare
make docker-pull
popd

tar -czvf targets-semis-aixcc-sc-challenge-004-full-nginx-cp.tar.gz -C targets-semis-aixcc-sc-challenge-004-full-nginx-cp .

# Create the folder for the backup restore
mkdir -p ./backup/invariant_build.target_with_sources && mv targets-semis-aixcc-sc-challenge-004-full-nginx-cp.tar.gz ./backup/invariant_build.target_with_sources/1.tar.gz

# Restore the backup from the artifacts!
pd restore ./backup --all

(timeout -s INT 10m pd --fail-fast --debug-trace --verbose run 2>&1 | tee pd.logs )&
RUN_PID=$!

function fail() {
    pkill -9 -P $RUN_PID || true
    kill -9 $RUN_PID || true
    docker ps -a --filter "ancestor=aixcc-invariantguy" -q | xargs -r docker rm -f || true
    docker ps -a --filter "ancestor=aixcc-invariantguy-build-nginx-004" -q | xargs -r docker rm -f || true
    exit 1
}
trap fail SIGINT

function success() {
    pkill -9 -P $RUN_PID || true
    kill -9 $RUN_PID || true
    docker ps -a --filter "ancestor=aixcc-invariantguy" -q | xargs -r docker rm -f || true
    docker ps -a --filter "ancestor=aixcc-invariantguy-build-nginx-004" -q | xargs -r docker rm -f || true
    exit 0
}

########################## BUILD ##########################

if [ $(pd ls invariant_build.target_with_sources | wc -l) -ne 1 ]; then
    echo " 🤡 INVARIANT BUILD FOR NGINX IS MISSING REQUIRED INPUT invariant_build.target_with_sources"
    fail
elif [ $(pd ls invariant_build.project_id | wc -l) -ne 1 ]; then
    echo " 🤡 INVARIANT BUILD FOR NGINX IS MISSING REQUIRED INPUT invariant_build.project_id"
    fail
elif [ $(pd ls invariant_build.target_metadata | wc -l) -ne 1 ]; then
    echo " 🤡 INVARIANT BUILD FOR NGINX IS MISSING REQUIRED INPUT invariant_build.target_metadata"
    fail
fi

# wait for build to finish
while [ $(pd ls invariant_build.done | wc -l) -eq 0 ]; do
    echo " 😴 Still building NGINX...."
    sleep 5
done

# check if build was successful
if [ $(pd ls invariant_build.success | wc -l) -eq 0 ]; then
    echo " 🤡 INVGUY BUILD FOR NGINX FAILED"
    fail
elif [ $(pd ls invariant_build.target_built_with_instrumentation | wc -l) -ne 1 ]; then
    echo " 🤡 INVGUY BUILD FOR NGINX IS MISSING OUTPUT invariant_build.target_built_with_instrumentation"
    fail
fi

echo " ✅ SUCCESS BUILDING INVGUY-NGINX"


if [ $(pd ls invariant_find_c.vds_record | wc -l) -eq 0 ]; then
    echo " 🤡 INVGUY FIND INVARIANTS FOR NGINX IS MISSING REQUIRED INPUT invariant_find_c.vds_record"
    fail
elif [ $(pd ls invariant_find_c.crashing_commit | wc -l) -eq 0 ]; then
    echo " 🤡 INVGUY FIND INVARIANTS FOR NGINX IS MISSING REQUIRED INPUT invariant_find_c.crashing_commit"
    fail
elif [ $(pd ls invariant_find_c.poi_report | wc -l) -eq 0 ]; then
    echo " 🤡 INVGUY FIND INVARIANTS FOR NGINX IS MISSING REQUIRED INPUT invariant_find_c.poi_report"
    fail
elif [ $(pd ls invariant_find_c.similar_harness_inputs_dir | wc -l ) -eq 0 ]; then
    echo " 🤡 INVGUY FIND INVARIANTS FOR NGINX IS MISSING (SIMILAR) BENING INPUTS"
    fail
fi

# wait for invariant_find_c to finish
while [ $(pd ls invariant_find_c.done | wc -l) -eq 0 ]; do
    echo " 😴 Still finding invariants for NGINX...."
    sleep 5
done

# ok, check if everything is ok!
report_content=$(pd cat invariant_find_c.invariant_report 5a7ec31d3f83084615b96cbd331d0661.);
# check if the report is not empty
if [ $(echo $report_content | wc -m) -eq 0 ]; then
    echo " 🤡 INVGUY FIND INVARIANTS FOR NGINX HAS EMPTY REPORT"
    fail
fi

# Check for the specific string in the report content
if echo "$report_content" | grep -q "min(auth_logs)==6"; then
    echo "🥳 Found the right invariant in the report content!"
else
    echo "🤡 The string 'min(auth_logs)==6 was NOT found in the report content."
    fail
fi

echo " ✅ SUCCESS FINDING INVARIANTS FOR NGINX"

echo "Invariants report:"
echo $report_content

success

