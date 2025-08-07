#!/bin/bash

echo WARNING: this will run, but there is no overlap between the benign coverages and the poi stack trace
echo TODO: it would be great to have better seeds to test this
echo Press any key to continue
read -n 1 -s

set -x
set -e

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
LOCAL_TEST=0

# define the variable only if we are local testing
if [ -z "$GITHUB_STEP_SUMMARY" ]; then
    GITHUB_STEP_SUMMARY="/proc/self/fd/1"
    LOCAL_TEST=1
fi

# If LOCAL_TEST is set, we are running locally
# let's wipe the harden container
if [ $LOCAL_TEST -eq 1 ]; then
    sudo rm -rf /shared/

    pushd ../..
        docker build -t aixcc-coverageguy .
    popd 

fi

cd "$SCRIPT_DIR"
docker ps 
pdl --unlock || rm -rf pipeline.lock
pdl --ignore-required --name coverage_testing_harden_demo2

if [ -d ./backup ]; then
    echo "Restoring from backup"
    pd restore ./backup/ --all
fi

# THE FOLLOWING IS TO TEST COVERAGE QUERY
pd inject coverage_query.vds_record 001 < targets-semis-aixcc-harden-demo2-vds-record-id.yaml
pd inject coverage_query.crashing_commit 005 < targets-semis-aixcc-harden-demo2-crashing-commit.yaml
pd inject coverage_query.poi_report 006 < targets-semis-aixcc-harden-demo2-poi-report-meta.yaml
pd inject coverage_query.harness_info 911 < targets-semis-aixcc-harden-demo2-harness-info.yaml
########################## TESTING ##########################

(pd --fail-fast --debug-trace --verbose run 2>&1 | tee pd.logs )&
RUN_PID=$!

function fail() {
    pkill -9 -P $RUN_PID || true
    kill -9 $RUN_PID || true
    docker ps -a --filter "ancestor=aixcc-coverageguy" -q | xargs -r docker rm -f || true
    docker ps -a --filter "ancestor=aixcc-coverageguy-build-*" -q | xargs -r docker rm -f || true
    exit 1
}

function success() {
    pkill -9 -P $RUN_PID || true
    kill -9 $RUN_PID || true
    docker ps -a --filter "ancestor=aixcc-coverageguy" -q | xargs -r docker rm -f || true
    docker ps -a --filter "ancestor=aixcc-coverageguy-build-*" -q | xargs -r docker rm -f || true
    exit 0
}

function run-check() {
    if ps -p $RUN_PID > /dev/null
    then
        pd status
        docker ps
    else
        wait $RUN_PID
        status=$?
        echo "echo $status"
        pd status

        pd cat coverage_build.logs 004
        pd cat coverage_build.done 004 

        docker ps
        (docker ps -q | xargs -L 1 docker logs) || true
        cat pd.logs
        echo "🤡 \`pd run\` stopped" >> $GITHUB_STEP_SUMMARY
        exit 1
    fi
}

########################## QUERY ##########################
# coverage_query.vds_record 1
# coverage_query.crashing_commit 1
# coverage_query.poi_report 1
# coverage_query.benign_harness_inputs 3
# coverage_query.benign_coverages 3

if [ $(pd ls coverage_query.vds_record | wc -l) -ne 1 ]; then
   echo " 🤡 COVERAGE QUERY FOR HARDEN IS MISSING REQUIRED INPUT coverage_query.vds_record" >> $GITHUB_STEP_SUMMARY
   fail
elif [ $(pd ls coverage_query.crashing_commit | wc -l) -ne 1 ]; then
   echo " 🤡 COVERAGE QUERY FOR HARDEN IS MISSING REQUIRED INPUT coverage_query.crashing_commit" >> $GITHUB_STEP_SUMMARY
   fail
elif [ $(pd ls coverage_query.poi_report | wc -l) -ne 1 ]; then
   echo " 🤡 COVERAGE QUERY FOR HARDEN IS MISSING REQUIRED INPUT coverage_query.poi_report" >> $GITHUB_STEP_SUMMARY
   fail
elif [ $(pd ls coverage_query.benign_harness_inputs | wc -l) -ne 3 ]; then
   echo " 🤡 COVERAGE QUERY FOR HARDEN IS MISSING REQUIRED INPUT coverage_query.benign_harness_inputs" >> $GITHUB_STEP_SUMMARY
   fail
elif [ $(pd ls coverage_query.benign_coverages | wc -l) -ne 3 ]; then
   echo " 🤡 COVERAGE QUERY FOR HARDEN IS MISSING REQUIRED INPUT coverage_query.benign_coverages" >> $GITHUB_STEP_SUMMARY
   fail
fi

# wait for query to finish
while [ $(pd ls coverage_query.done | wc -l) -eq 0 ]; do
   echo " 😴 Still querying coverage for HARDEN...." >> $GITHUB_STEP_SUMMARY
   sleep 5
   #run-check
done

# check if build was successful
# coverage_query.similar_harness_inputs_dir 1
if [ $(pd ls coverage_query.success | wc -l) -eq 0 ]; then
   echo " 🤡 COVERAGE QUERY FOR HARDEN FAILED" >> $GITHUB_STEP_SUMMARY
   fail
elif [ $(pd ls coverage_query.similar_harness_inputs_dir | wc -l) -ne 1 ]; then
   echo " 🤡 COVERAGE QUERY FOR HARDEN IS MISSING OUTPUT coverage_query.similar_harness_inputs_dir" >> $GITHUB_STEP_SUMMARY
   fail
fi

# (arbitrarily) confirm that all benign inputs but the filtered one are "similar" to the crash (in this test)
# This 
SIMILAR_HARNESS_INPUTS_DIR=$(pd ls coverage_query.similar_harness_inputs_dir)
NUM_SIMILAR_HARNESS_INPUTS=$(pd cat coverage_query.similar_harness_inputs_dir $SIMILAR_HARNESS_INPUTS_DIR | tar -t | grep -v '^./$' | wc -l)
if [ $NUM_SIMILAR_HARNESS_INPUTS -ne 2 ]; then
   echo $(pd ls coverage_query.similar_harness_inputs_dir)
   echo " 🤡 COVERAGE QUERY FOR HARDEN FAILED -- TOO FEW SIMILAR INPUTS ($NUM_SIMILAR_HARNESS_INPUTS)" >> $GITHUB_STEP_SUMMARY
   fail
fi

#run-check
echo " ✅ SUCCESS QUERYING COVERAGE FOR HARDEN" >> $GITHUB_STEP_SUMMARY

echo "Similar seeds:"
pd cat coverage_query.similar_harness_inputs_dir $SIMILAR_HARNESS_INPUTS_DIR | tar -t | grep -v '^./$'

success


# NOTE:
# b001 is benign seed with right harness (911)
# b002 is benign seed with right harness (911)
# b003 is benign seed with wrong harness (912)
# b001 is crashing seed