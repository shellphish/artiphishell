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
# let's wipe the mock-cp container
if [ $LOCAL_TEST -eq 1 ]; then

    containers=$(docker ps -aq --filter "name=aixcc-invariantguy")
    [ -n "$containers" ] && echo "$containers" | xargs docker rm -f || true
    images=$(docker images -q aixcc-coverageguy)
    [ -n "$images" ] && echo "$images" | xargs docker rmi --force || true

    pushd ../..
        docker build -t aixcc-invariantguy .
    popd 

    sudo rm -rf /shared/

fi

cd "$SCRIPT_DIR"

pdl --ignore-required

if [ ! -f targets-semis-harden-demo3-cp.tar.gz ]; then
    if [ ! -d targets-semis-harden-demo3 ]; then
        git clone https://github.com/shellphish-support-syndicate/targets-semis-harden-demo3
        pushd targets-semis-harden-demo3
        make cpsrc-prepare
        
        if [ $LOCAL_TEST -eq 1 ]; then
            make docker-pull
        fi
        
        popd
    fi
    tar -czvf targets-semis-harden-demo3-cp.tar.gz -C targets-semis-harden-demo3 .
fi

if [ -d ./backup ]; then
     pd restore ./backup/ --all
fi


########################## THE FOLLOWING IS TO TEST BUILD_INVGUY ##########################
pd inject invariant_build.target_with_sources 004 < targets-semis-harden-demo3-cp.tar.gz
pd inject invariant_build.target_metadata 004 < targets-semis-harden-demo3-cp-metadata.json
pd inject invariant_build.project_id 004 < targets-semis-harden-demo3-cp-image-ready.yaml
pd inject invariant_build.full_functions_indices 004 < /dev/null
# pd inject invariant_build.target_built_with_instrumentation 004 < targets-semis-harden-demo3-cp-built-with-instrumentation.tar.gz
# pd inject invariant_build.done 004 < targets-semis-harden-demo3-cp-done.yaml

########################## FIND INVARIANTS ##########################
#pd inject invariant_build.success 004 < targets-semis-aixcc-sc-challenge-002-KERNEL-HARDEN-cp-build-invguy-done.yaml
#pd inject invariant_build.target_built_with_instrumentation 004 < targets-semis-aixcc-sc-challenge-002-KERNEL-HARDEN-cp-built-with-perf.tar.gz

pd inject invariant_find_kernel.vds_record 001 < targets-semis-harden-demo3-cp-vds-record-id.yaml
pd inject invariant_find_kernel.crashing_commit 005 < targets-semis-harden-demo3-cp-crashing-commit.yaml
pd inject invariant_find_kernel.poi_report 006 < targets-semis-harden-demo3-cp-poi-report.yaml
pd inject invariant_find_kernel.functions_by_file_index 004 < targets-semis-harden-demo3-cp-functions_by_file_index_json.json  

pd --verbose run &
RUN_PID=$!

# define the variable only if it is not defined
if [ -z "$GITHUB_STEP_SUMMARY" ]; then
    GITHUB_STEP_SUMMARY="/proc/self/fd/1"
fi

function fail() {
    kill $RUN_PID
    exit 1
}

function success() {
    exit 0
}

######################### BUILD ##########################

if [ $(pd ls invariant_build.target_with_sources | wc -l) -ne 1 ]; then
    echo " 🤡 COVERAGE BUILD FOR KERNEL-HARDEN IS MISSING REQUIRED INPUT invariant_build.target_with_sources" >> $GITHUB_STEP_SUMMARY
    fail
elif [ $(pd ls invariant_build.project_id | wc -l) -ne 1 ]; then
    echo " 🤡 COVERAGE BUILD FOR KERNEL-HARDEN IS MISSING REQUIRED INPUT invariant_build.project_id" >> $GITHUB_STEP_SUMMARY
    fail
elif [ $(pd ls invariant_build.target_metadata | wc -l) -ne 1 ]; then
    echo " 🤡 COVERAGE BUILD FOR KERNEL-HARDEN IS MISSING REQUIRED INPUT invariant_build.target_metadata" >> $GITHUB_STEP_SUMMARY
    fail
fi

# wait for build to finish
while [ $(pd ls invariant_build.done | wc -l) -eq 0 ]; do
    echo " 😴 Still building KERNEL-HARDEN...." >> $GITHUB_STEP_SUMMARY
    sleep 5
done

# check if build was successful
# coverage_build_c.target_built_with_coverage 1
if [ $(pd ls invariant_build.success | wc -l) -eq 0 ]; then
    echo " 🤡 INVGUY BUILD FOR KERNEL-HARDEN FAILED" >> $GITHUB_STEP_SUMMARY
    fail
elif [ $(pd ls invariant_build.target_built_with_instrumentation | wc -l) -ne 1 ]; then
    echo " 🤡 INVGUY BUILD FOR KERNEL-HARDEN IS MISSING OUTPUT invariant_build.target_built_with_instrumentation" >> $GITHUB_STEP_SUMMARY
    fail
fi

echo " ✅ SUCCESS BUILDING INVGUY-KERNEL-HARDEN" >> $GITHUB_STEP_SUMMARY


if [ $(pd ls invariant_find_kernel.vds_record | wc -l) -ne 1 ]; then
    echo " 🤡 INVGUY FIND INVARIANTS FOR KERNEL-HARDEN IS MISSING REQUIRED INPUT invariant_find_kernel.vds_record" >> $GITHUB_STEP_SUMMARY
    fail
elif [ $(pd ls invariant_find_kernel.crashing_commit | wc -l) -ne 1 ]; then
    echo " 🤡 INVGUY FIND INVARIANTS FOR KERNEL-HARDEN IS MISSING REQUIRED INPUTinvariant_find_kernel.crashing_commit" >> $GITHUB_STEP_SUMMARY
    fail
elif [ $(pd ls invariant_find_kernel.poi_report | wc -l) -ne 1 ]; then
    echo " 🤡 INVGUY FIND INVARIANTS FOR KERNEL-HARDEN IS MISSING REQUIRED INPUT invariant_find_kernel.poi_report" >> $GITHUB_STEP_SUMMARY
    fail
elif [ $(pd ls invariant_find_kernel.similar_harness_inputs_dir | wc -l ) -eq 0 ]; then
    echo " 🤡 INVGUY FIND INVARIANTS FOR KERNEL-HARDEN IS MISSING BENING INPUTS" >> $GITHUB_STEP_SUMMARY
    fail
fi

# wait for invariant_find_kernel to finish
while [ $(pd ls invariant_find_kernel.done | wc -l) -eq 0 ]; do
    echo " 😴 Still finding invariants for KERNEL-HARDEN...." >> $GITHUB_STEP_SUMMARY
    sleep 5
done

# ok, check if everything is ok!
report_content=$(pd cat invariant_find_kernel.invariant_report 001); 
# check if the report is not empty
if [ $(echo $report_content | wc -m) -eq 0 ]; then
    echo " 🤡 INVGUY FIND INVARIANTS FOR KERNEL-HARDEN HAS EMPTY REPORT" >> $GITHUB_STEP_SUMMARY
    fail
fi

echo " ✅ SUCCESS FINDING INVARIANTS FOR KERNEL-HARDEN" >> $GITHUB_STEP_SUMMARY

success