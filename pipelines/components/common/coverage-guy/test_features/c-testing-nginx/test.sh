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
    pd rm coverage_trace __all__ &> /dev/null || true
    sudo rm -rf /shared/

    pushd ../..
        docker build -t aixcc-coverageguy .
    popd 

fi

cd "$SCRIPT_DIR"
docker ps 
pdl --unlock || rm -rf pipeline.lock
pdl --ignore-required --name coverage_testing_nginx

if [ ! -f targets-semis-aixcc-sc-challenge-004-nginx-cp.tar.gz ]; then
    if [ ! -d targets-semis-aixcc-sc-challenge-004-nginx-cp ]; then
        git clone https://github.com/shellphish-support-syndicate/targets-semis-aixcc-sc-challenge-004-nginx-cp
        pushd targets-semis-aixcc-sc-challenge-004-nginx-cp
        make cpsrc-prepare
        if [ $LOCAL_TEST -eq 1 ]; then
            make docker-pull
        fi
        popd
    fi
    tar -czvf targets-semis-aixcc-sc-challenge-004-nginx-cp.tar.gz -C targets-semis-aixcc-sc-challenge-004-nginx-cp .
fi

if [ -d ./backup ]; then
    echo "Restoring from backup"
    pd restore ./backup/ --all
fi


# THE FOLLOWING IS TO TEST COVERAGE BUILD
pd inject coverage_build.target 004 < targets-semis-aixcc-sc-challenge-004-nginx-cp.tar.gz
pd inject coverage_build.target_id 004 < /dev/null
pd inject coverage_build.target_metadatum 004 < targets-semis-aixcc-sc-challenge-004-nginx-cp-metadata.json
pd inject coverage_build.full_functions_indices 004 < /dev/null
# THE FOLLOWING IS TO TEST COVERAGE QUERY
pd inject coverage_trace.harness_info 911 < targets-semis-aixcc-sc-challenge-004-nginx-cp-harness-info.yaml
pd inject coverage_trace.functions_index 004 < /dev/null
########################## TESTING ##########################

(pd --fail-fast --debug-trace --verbose run 2>&1 | tee pd.logs )&
RUN_PID=$!

function fail() {
    pkill -9 -P $RUN_PID || true
    kill -9 $RUN_PID || true
    docker ps -a --filter "ancestor=aixcc-coverageguy" -q | xargs -r docker rm -f || true
    docker ps -a --filter "ancestor=aixcc-coverageguy-build-nginx-004" -q | xargs -r docker rm -f || true
    exit 1
}
trap fail SIGINT

function success() {
    pkill -9 -P $RUN_PID || true
    kill -9 $RUN_PID || true
    docker ps -a --filter "ancestor=aixcc-coverageguy" -q | xargs -r docker rm -f || true
    docker ps -a --filter "ancestor=aixcc-coverageguy-build-nginx-004" -q | xargs -r docker rm -f || true
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
        
        pd cat coverage_trace.logs 004
        pd cat coverage_trace.done 004

        
        docker ps
        (docker ps -q | xargs -L 1 docker logs) || true
        cat pd.logs
        echo "🤡 \`pd run\` stopped" >> $GITHUB_STEP_SUMMARY
        exit 1
    fi
}


########################## BUILD ##########################
# coverage_build.target_id 1
# coverage_build.target 1
# coverage_build.target_metadatum 1
# check if different from 1

if [ $(pd ls coverage_build.target | wc -l) -ne 1 ]; then
    echo " 🤡 COVERAGE BUILD FOR NGINX IS MISSING REQUIRED INPUT coverage_build.target" >> $GITHUB_STEP_SUMMARY
    fail
elif [ $(pd ls coverage_build.target_id | wc -l) -ne 1 ]; then
    echo " 🤡 COVERAGE BUILD FOR NGINX IS MISSING REQUIRED INPUT coverage_build.target_id" >> $GITHUB_STEP_SUMMARY
    fail
elif [ $(pd ls coverage_build.target_metadatum | wc -l) -ne 1 ]; then
    echo " 🤡 COVERAGE BUILD FOR NGINX IS MISSING REQUIRED INPUT coverage_build.target_metadatum" >> $GITHUB_STEP_SUMMARY
    fail
fi
#run-check

# wait for build to finish
while [ $(pd ls coverage_build.done | wc -l) -eq 0 ]; do
    echo " 😴 Still building NGINX...." >> $GITHUB_STEP_SUMMARY
    #pd status | grep coverage_build
    #docker ps -a | grep coverage_testing_nginx || true
    #docker logs $(docker ps -a | grep coverage_testing_nginx | grep coverage_build | awk '{print $1}' |grep -v CONTAINER | head -n 1) || true
    sleep 5
    #run-check
done

# check if build was successful
# coverage_build.target_built_with_coverage 1
if [ $(pd ls coverage_build.success | wc -l) -eq 0 ]; then
    echo " 🤡 COVERAGE BUILD FOR NGINX FAILED" >> $GITHUB_STEP_SUMMARY
    fail
elif [ $(pd ls coverage_build.target_built_with_coverage | wc -l) -ne 1 ]; then
    echo " 🤡 COVERAGE BUILD FOR NGINX IS MISSING OUTPUT coverage_build.target_built_with_coverage" >> $GITHUB_STEP_SUMMARY
    fail
fi

#run-check
echo " ✅ SUCCESS BUILDING NGINX" >> $GITHUB_STEP_SUMMARY

docker ps 


########################## TRACE ##########################
# coverage_trace.target_built_with_coverage 1
# coverage_trace.target_metadatum 1
# coverage_trace.benign_harness_inputs 3
# coverage_trace.benign_harness_inputs_metadata 3
# coverage_trace.crashing_harness_inputs 1
# coverage_trace.crashing_harness_inputs_metadata 1

if [ $(pd ls coverage_trace.target_built_with_coverage | wc -l) -ne 1 ]; then
    echo " 🤡 COVERAGE TRACE FOR NGINX IS MISSING REQUIRED INPUT coverage_trace.target_built_with_coverage" >> $GITHUB_STEP_SUMMARY
    fail
fi
if [ $(pd ls coverage_trace.target_metadatum | wc -l) -ne 1 ]; then
    echo " 🤡 COVERAGE TRACE FOR NGINX IS MISSING REQUIRED INPUT coverage_trace.target_metadatum" >> $GITHUB_STEP_SUMMARY
    fail
fi
if [ $(pd ls coverage_trace.benign_harness_inputs | wc -l) -ne 4 ]; then
    echo " 🤡 COVERAGE TRACE FOR NGINX IS MISSING REQUIRED INPUT coverage_trace.benign_harness_inputs" >> $GITHUB_STEP_SUMMARY
    fail
fi
if [ $(pd ls coverage_trace.benign_harness_inputs_metadata | wc -l) -ne 4 ]; then
    echo " 🤡 COVERAGE TRACE FOR NGINX IS MISSING REQUIRED INPUT coverage_trace.benign_harness_inputs_metadata" >> $GITHUB_STEP_SUMMARY
    fail
fi
if [ $(pd ls coverage_trace.crashing_harness_inputs | wc -l) -ne 1 ]; then
    echo " 🤡 COVERAGE TRACE FOR NGINX IS MISSING REQUIRED INPUT coverage_trace.crashing_harness_inputs" >> $GITHUB_STEP_SUMMARY
    fail
fi
if [ $(pd ls coverage_trace.crashing_harness_inputs_metadata | wc -l) -ne 1 ]; then
    echo " 🤡 COVERAGE TRACE FOR NGINX IS MISSING REQUIRED INPUT coverage_trace.crashing_harness_inputs_metadata" >> $GITHUB_STEP_SUMMARY
    fail
fi
#run-check

# wait for trace to finish (cannot check coverage_trace.done because this is a long running task)
# here we expect the report of the fake benign input to show up (and be empty!)
while [ $(pd ls coverage_trace.benign_coverages | wc -l) -lt 2 ]; do
    echo " 😴 Still collecting coverage for NGINX...." >> $GITHUB_STEP_SUMMARY
    sleep 5
    #run-check
done
#run-check

# check if build was successful
# coverage_trace.benign_coverages 3
# coverage_trace.crashing_coverages 1

if [ $(pd ls coverage_trace.benign_coverages | wc -l) -lt 2 ]; then
    # If we have less than 3 reports it means that we did not obtain the coverage
    # reports for the good benign inputs
    echo " 🤡 COVERAGE TRACE FOR NGINX IS MISSING OUTPUT coverage_trace.benign_coverages" >> $GITHUB_STEP_SUMMARY
    fail
elif [ $(pd ls coverage_trace.benign_coverages | wc -l) -eq 3 ]; then
    # the crashing benign MUST be flitered out, so, if we have 4 reports we are cursed.
    echo " 🤡 COVERAGE TRACE FOR NGINX FAILED: THE SEED CONDOM DID NOT WORK" >> $GITHUB_STEP_SUMMARY
    fail
elif [ $(pd ls coverage_trace.benign_coverages | grep b002 | wc -l) -eq 1 ]; then
    # the crashing benign MUST be flitered out, so, if we have 4 reports we are cursed.
    echo " 🤡 COVERAGE TRACE FOR NGINX FAILED: THE FILTERING SCOPE DID NOT WORK" >> $GITHUB_STEP_SUMMARY
    fail
fi
#run-check

# (arbitrarily) confirm that benign coverages are not empty
for file in $(pd ls coverage_trace.benign_coverages); do
    if [ $(pd cat coverage_trace.benign_coverages $file | wc -m) -eq 0 ]; then
        echo " 🤡 The file $file is empty!" >> $GITHUB_STEP_SUMMARY
        echo " 🤡 COVERAGE TRACE FOR NGINX HAS EMPTY coverage_trace.benign_coverages" >> $GITHUB_STEP_SUMMARY
        fail
    fi
done

docker ps 
#run-check
echo " ✅ SUCCESS COLLECTING COVERAGE FOR NGINX" >> $GITHUB_STEP_SUMMARY


# THE FOLLOWING IS TO TEST COVERAGE QUERY
pd inject coverage_query.vds_record 001 < targets-semis-aixcc-sc-challenge-004-nginx-cp-vds-record-id.yaml
pd inject coverage_query.crashing_commit 005 < targets-semis-aixcc-sc-challenge-004-nginx-cp-crashing-commit.yaml
pd inject coverage_query.poi_report 006 < targets-semis-aixcc-sc-challenge-004-nginx-cp-poi-report-meta.yaml
########################## QUERY ##########################
# coverage_query.vds_record 1
# coverage_query.crashing_commit 1
# coverage_query.poi_report 1
# coverage_query.benign_harness_inputs 3
# coverage_query.benign_coverages 3


if [ $(pd ls coverage_query.vds_record | wc -l) -ne 1 ]; then
   echo " 🤡 COVERAGE QUERY FOR NGINX IS MISSING REQUIRED INPUT coverage_query.vds_record" >> $GITHUB_STEP_SUMMARY
   fail
elif [ $(pd ls coverage_query.crashing_commit | wc -l) -ne 1 ]; then
   echo " 🤡 COVERAGE QUERY FOR NGINX IS MISSING REQUIRED INPUT coverage_query.crashing_commit" >> $GITHUB_STEP_SUMMARY
   fail
elif [ $(pd ls coverage_query.poi_report | wc -l) -ne 1 ]; then
   echo " 🤡 COVERAGE QUERY FOR NGINX IS MISSING REQUIRED INPUT coverage_query.poi_report" >> $GITHUB_STEP_SUMMARY
   fail
elif [ $(pd ls coverage_query.benign_harness_inputs | wc -l) -ne 4 ]; then
   echo " 🤡 COVERAGE QUERY FOR NGINX IS MISSING REQUIRED INPUT coverage_query.benign_harness_inputs" >> $GITHUB_STEP_SUMMARY
   fail
elif [ $(pd ls coverage_query.benign_coverages | wc -l) -ne 2 ]; then
   echo " 🤡 COVERAGE QUERY FOR NGINX IS MISSING REQUIRED INPUT coverage_query.benign_coverages" >> $GITHUB_STEP_SUMMARY
   fail
fi

# wait for query to finish
while [ $(pd ls coverage_query.done | wc -l) -eq 0 ]; do
   echo " 😴 Still querying coverage for NGINX...." >> $GITHUB_STEP_SUMMARY
   sleep 5
   #run-check
done

# check if build was successful
# coverage_query.similar_harness_inputs_dir 1
if [ $(pd ls coverage_query.success | wc -l) -eq 0 ]; then
   echo " 🤡 COVERAGE QUERY FOR NGINX FAILED" >> $GITHUB_STEP_SUMMARY
   fail
elif [ $(pd ls coverage_query.similar_harness_inputs_dir | wc -l) -ne 1 ]; then
   echo " 🤡 COVERAGE QUERY FOR NGINX IS MISSING OUTPUT coverage_query.similar_harness_inputs_dir" >> $GITHUB_STEP_SUMMARY
   fail
fi

# (arbitrarily) confirm that all benign inputs but the filtered one are "similar" to the crash (in this test)
# This 
SIMILAR_HARNESS_INPUTS_DIR=$(pd ls coverage_query.similar_harness_inputs_dir)
if [ $(pd cat coverage_query.similar_harness_inputs_dir $SIMILAR_HARNESS_INPUTS_DIR | tar -t | grep -v '^./$' | wc -l) -ne 2 ]; then
   echo $(pd ls coverage_query.similar_harness_inputs_dir)
   echo " 🤡 COVERAGE QUERY FOR NGINX FAILED -- TOO FEW SIMILAR INPUTS" >> $GITHUB_STEP_SUMMARY
   fail
fi

#run-check
echo " ✅ SUCCESS QUERYING COVERAGE FOR NGINX" >> $GITHUB_STEP_SUMMARY

echo "Similar seeds:"
pd cat coverage_query.similar_harness_inputs_dir $SIMILAR_HARNESS_INPUTS_DIR | tar -t | grep -v '^./$'

success