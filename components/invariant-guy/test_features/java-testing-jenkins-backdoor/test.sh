#!/bin/bash

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
# let's wipe the jenkins container
if [ $LOCAL_TEST -eq 1 ]; then

    sudo rm -rf /shared/

    pushd ../..
        docker build -t aixcc-invariantguy .
    popd 

fi

cd "$SCRIPT_DIR"

pdl --ignore-required

if [ ! -f targets-semis-aixcc-sc-challenge-002-jenkins-cp.tar.gz ]; then
    if [ ! -d targets-semis-aixcc-sc-challenge-002-jenkins-cp ]; then
        git clone https://github.com/shellphish-support-syndicate/targets-semis-aixcc-sc-challenge-002-jenkins-cp
        pushd targets-semis-aixcc-sc-challenge-002-jenkins-cp
        make cpsrc-prepare
        if [ $LOCAL_TEST -eq 1 ]; then
            make docker-pull
        fi
        popd
    fi
    tar -czvf targets-semis-aixcc-sc-challenge-002-jenkins-cp.tar.gz -C targets-semis-aixcc-sc-challenge-002-jenkins-cp .
fi

if [ -d ./backup ]; then
     pd restore ./backup/ --all
fi


########################## THE FOLLOWING IS TO TEST BUILD_INVGUY ##########################
pd inject invariant_build.target_with_sources 004 < targets-semis-aixcc-sc-challenge-002-jenkins-cp.tar.gz
pd inject invariant_build.target_metadata 004 < targets-semis-aixcc-sc-challenge-002-jenkins-cp-metadata.json
pd inject invariant_build.project_id 004 < /dev/null
pd inject invariant_build.full_functions_indices 004 < /dev/null

########################## FIND INVARIANTS ##########################
#pd inject invariant_build.success 004 < targets-semis-aixcc-sc-challenge-002-jenkins-cp-build-invguy-done.yaml
#pd inject invariant_build.target_built_with_instrumentation 004 < targets-semis-aixcc-sc-challenge-002-jenkins-cp-built-with-perf.tar.gz

pd inject invariant_find_java.vds_record 001 < targets-semis-aixcc-sc-challenge-002-jenkins-cp-vds-record-id.yaml
pd inject invariant_find_java.crashing_commit 005 < targets-semis-aixcc-sc-challenge-002-jenkins-cp-crashing-commit.yaml
pd inject invariant_find_java.poi_report 006 < targets-semis-aixcc-sc-challenge-002-jenkins-cp-poi-report.yaml
pd inject invariant_find_java.functions_by_file_index 004 < targets-semis-aixcc-sc-challenge-002-jenkins-cp-functions_by_file_index_json.json  

(pd --fail-fast --debug-trace --verbose run 2>&1 | tee pd.logs )&
RUN_PID=$!

function fail() {
    # pd rm coverage_trace __all__ &> /dev/null || true
    pkill -9 -P $RUN_PID || true
    kill -9 $RUN_PID || true
    docker ps -a --filter "ancestor=aixcc-invariantguy" -q | xargs -r docker rm -f || true
    docker ps -a --filter "ancestor=aixcc-invariantguy-build-jenkins-004" -q | xargs -r docker rm -f || true
    exit 1
}
trap fail SIGINT

function success() {
    # pd rm coverage_trace __all__ &> /dev/null || true
    pkill -9 -P $RUN_PID || true
    kill -9 $RUN_PID || true
    docker ps -a --filter "ancestor=aixcc-invariantguy" -q | xargs -r docker rm -f || true
    docker ps -a --filter "ancestor=aixcc-invariantguy-build-jenkins-004" -q | xargs -r docker rm -f || true
    exit 0
}

######################### BUILD ##########################

if [ $(pd ls invariant_build.target_with_sources | wc -l) -ne 1 ]; then
    echo " 🤡 COVERAGE BUILD FOR JENKINS IS MISSING REQUIRED INPUT invariant_build.target_with_sources" >> $GITHUB_STEP_SUMMARY
    fail
elif [ $(pd ls invariant_build.project_id | wc -l) -ne 1 ]; then
    echo " 🤡 COVERAGE BUILD FOR JENKINS IS MISSING REQUIRED INPUT invariant_build.project_id" >> $GITHUB_STEP_SUMMARY
    fail
elif [ $(pd ls invariant_build.target_metadata | wc -l) -ne 1 ]; then
    echo " 🤡 COVERAGE BUILD FOR JENKINS IS MISSING REQUIRED INPUT invariant_build.target_metadata" >> $GITHUB_STEP_SUMMARY
    fail
fi

# wait for build to finish
while [ $(pd ls invariant_build.done | wc -l) -eq 0 ]; do
    echo " 😴 Still building JENKINS...." >> $GITHUB_STEP_SUMMARY
    sleep 5
done

# check if build was successful
# coverage_build_c.target_built_with_coverage 1
if [ $(pd ls invariant_build.success | wc -l) -eq 0 ]; then
    echo " 🤡 INVGUY BUILD FOR JENKINS FAILED" >> $GITHUB_STEP_SUMMARY
    fail
elif [ $(pd ls invariant_build.target_built_with_instrumentation | wc -l) -ne 1 ]; then
    echo " 🤡 INVGUY BUILD FOR JENKINS IS MISSING OUTPUT invariant_build.target_built_with_instrumentation" >> $GITHUB_STEP_SUMMARY
    fail
fi

echo " ✅ SUCCESS BUILDING INVGUY-JENKINS" >> $GITHUB_STEP_SUMMARY


if [ $(pd ls invariant_find_java.vds_record | wc -l) -ne 1 ]; then
    echo " 🤡 INVGUY FIND INVARIANTS FOR JENKINS IS MISSING REQUIRED INPUT invariant_find_java.vds_record" >> $GITHUB_STEP_SUMMARY
    fail
elif [ $(pd ls invariant_find_java.crashing_commit | wc -l) -ne 1 ]; then
    echo " 🤡 INVGUY FIND INVARIANTS FOR JENKINS IS MISSING REQUIRED INPUTinvariant_find_java.crashing_commit" >> $GITHUB_STEP_SUMMARY
    fail
elif [ $(pd ls invariant_find_java.poi_report | wc -l) -ne 1 ]; then
    echo " 🤡 INVGUY FIND INVARIANTS FOR JENKINS IS MISSING REQUIRED INPUT invariant_find_java.poi_report" >> $GITHUB_STEP_SUMMARY
    fail
elif [ $(pd ls invariant_find_java.similar_harness_inputs_dir | wc -l ) -eq 0 ]; then
    echo " 🤡 INVGUY FIND INVARIANTS FOR JENKINS IS MISSING (SIMILAR) BENING INPUTS" >> $GITHUB_STEP_SUMMARY
    fail
fi

# wait for invariant_find_java to finish
while [ $(pd ls invariant_find_java.done | wc -l) -eq 0 ]; do
    echo " 😴 Still finding invariants for JENKINS...." >> $GITHUB_STEP_SUMMARY
    sleep 5
done

# ok, check if everything is ok!
report_content=$(pd cat invariant_find_java.invariant_report 001); 
# check if the report is not empty
if [ $(echo $report_content | wc -m) -eq 0 ]; then
    echo " 🤡 INVGUY FIND INVARIANTS FOR JENKINS HAS EMPTY REPORT" >> $GITHUB_STEP_SUMMARY
    fail
fi

echo " ✅ SUCCESS FINDING INVARIANTS FOR JENKINS" >> $GITHUB_STEP_SUMMARY

echo "Invaiants report:"
echo $report_content

success