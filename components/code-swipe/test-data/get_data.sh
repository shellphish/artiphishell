#!/bin/bash

cd $(dirname $0)

set -ex

# Require TARGET and RUN as arguments
if [ -z "$1" ] || [ -z "$2" ] || [-z "$3"]; then
    echo "Usage: $0 <TARGET> <RUN> <MODE>" &2
    exit 1
fi

TARGET="$1"
RUN="$2"
MODE="$3"

echo "Using TARGET=$TARGET"
echo "Using RUN=$RUN"
echo "MODE=$MODE"

JOB=$(curl https://aixcc-diskman.adamdoupe.com/iKbr6hfymftxL7pr3FEX/pipeline-backup/${TARGET}/${RUN}/analyze_target.project_analysis_sources/ -s | grep href= | tail -n +2 | cut -d'"' -f2 | cut -d'.' -f1)
DEBUG_BUILD_JOB=$(curl https://aixcc-diskman.adamdoupe.com/iKbr6hfymftxL7pr3FEX/pipeline-backup/${TARGET}/${RUN}/debug_build.debug_build_artifacts/ -s | grep href= | tail -n +2 | cut -d'"' -f2 | cut -d'.' -f1)

function get_repo_tar() {
    local REPO=$1
    local JOB=$2
    # Check if we already have this downloaded
    if [ -f $REPO/.from-run ]; then
        if [ $(cat $REPO/.from-run) == $RUN ]; then
            echo "Already downloaded $REPO/$JOB"
            return
        fi
    fi

    if [ -d $REPO ]; then
        rm -rf $REPO
    fi
    mkdir -p $REPO/$JOB

    wget https://aixcc-diskman.adamdoupe.com/iKbr6hfymftxL7pr3FEX/pipeline-backup/${TARGET}/${RUN}/${REPO}/${JOB}.tar.gz \
        -O $REPO/$JOB.tar.gz
    tar -xf $REPO/$JOB.tar.gz -C $REPO/$JOB
    rm $REPO/$JOB.tar.gz
    echo $RUN > $REPO/.from-run
}

function get_tar_general() {
    local NAME=$1
    if [ -f $NAME/.from-run ]; then
        if [ $(cat $NAME/.from-run) == $RUN ]; then
            echo "Already downloaded $NAME"
            return
        fi
    fi

    if [ -d $NAME ]; then
        rm -rf $NAME
    fi
    mkdir -p $NAME

    wget https://aixcc-diskman.adamdoupe.com/iKbr6hfymftxL7pr3FEX/pipeline-backup/${TARGET}/${RUN}/${NAME}.tar.gz \
        -O $NAME/$NAME.tar.gz
    tar -xf $NAME/$NAME.tar.gz -C $NAME/
    rm $NAME/$NAME.tar.gz
    echo $RUN > $NAME/.from-run
}

function get_repo_blob() {
    local REPO=$1
    local JOB=$2
    local EXT=$3
    if [ -d $REPO ]; then
        rm -rf $REPO
    fi

    mkdir -p $REPO/
    wget https://aixcc-diskman.adamdoupe.com/iKbr6hfymftxL7pr3FEX/pipeline-backup/${TARGET}/${RUN}/${REPO}/${JOB}${EXT} \
        -O $REPO/$JOB${EXT}
}

BUILD_CONFIG=canonical

get_repo_tar analyze_target.project_analysis_sources $JOB
get_repo_tar canonical_build.project_oss_fuzz_repo $JOB

ARTIFACT_JOB=$JOB
if [ "$BUILD_CONFIG" == "debug" ]; then
    ARTIFACT_JOB=$DEBUG_BUILD_JOB
fi

get_repo_tar ${BUILD_CONFIG}_build.${BUILD_CONFIG}_build_artifacts $ARTIFACT_JOB

get_repo_blob generate_full_function_index.target_functions_index $JOB
get_repo_tar generate_full_function_index.target_functions_jsons_dir $JOB

mkdir -p $(pwd)/canonical_build.project_oss_fuzz_repo/$JOB/projects/$TARGET/
rm $(pwd)/canonical_build.project_oss_fuzz_repo/$JOB/projects/$TARGET/artifacts || true
ln -s \
  $(pwd)/${BUILD_CONFIG}_build.${BUILD_CONFIG}_build_artifacts/$JOB/ \
  $(pwd)/canonical_build.project_oss_fuzz_repo/$JOB/projects/$TARGET/artifacts

get_tar_general analysisgraph_1
sudo chown $USER:$USER -R analysisgraph_1
sudo chmod 777 -R analysisgraph_1

get_repo_blob generate_full_function_index.crs_task $JOB .yaml

get_repo_blob analyze_target.metadata_path $JOB .yaml

get_repo_blob quickseed_codeql_query.discovery_vuln_reports $JOB
if [ "$MODE" = "full"   ]; then
get_repo_blob codeql_cwe_queries.codeql_cwe_report $JOB

get_repo_blob semgrep_analysis.semgrep_analysis_report $JOB
fi

# Try to download scan_guy_full results with error handling
echo "Attempting to download scan_guy_full results..."
if ! get_repo_tar scan_guy_full.scan_guy_results $JOB; then
    echo "Warning: Failed to download scan_guy_full.scan_guy_results for job $JOB"
    echo "This may be expected if scan_guy_full data is not available for this job"
else
    echo "Successfully downloaded scan_guy_full.scan_guy_results"
fi

if [ "$MODE" = "delta"  ]; then
    get_repo_tar diffguy.diffguy_reports $JOB
    get_repo_blob generate_commit_function_index.target_functions_index $JOB
    get_repo_tar generate_commit_function_index.target_functions_jsons_dir $JOB

    # Download regular reports for delta mode
    get_repo_blob codeql_cwe_queries.codeql_cwe_report $JOB
    get_repo_blob semgrep_analysis.semgrep_analysis_report $JOB

    # Download base reports for delta mode
    get_repo_blob codeql_cwe_queries_base.codeql_cwe_report_base $JOB
    get_repo_blob semgrep_analysis_base.semgrep_analysis_report_base $JOB
fi
