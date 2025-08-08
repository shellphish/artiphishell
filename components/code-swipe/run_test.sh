#!/bin/bash

set -ex

SCRIPT_DIR=$(realpath $(dirname $0))

JOB=$(/bin/ls $SCRIPT_DIR/test-data/canonical_build.canonical_build_artifacts/ | grep -v '.tar.gz' | cut -d' ' -f1 | head -n 1)
#DEBUG_BUILD_JOB=$(/bin/ls $SCRIPT_DIR/test-data/debug_build.debug_build_artifacts/ | grep -v '.tar.gz' | cut -d' ' -f1 | head -n 1)


# Require TARGET and RUN as arguments
if [ -z "$1" ] || [ -z "$2" ]; then
    echo "Usage: $0 <PROJECT_NAME> <MODE>" >&2
    echo "  <PROJECT_NAME>: The name of the project (e.g., zip4j)" >&2
    echo "  <MODE>: The analysis mode, either 'full' or 'delta'" >&2
    echo "Example: $0 zip4j full" >&2
    exit 1
fi
export PROJECT_NAME=$1
export MODE=$2

export TARGET_DIR=$SCRIPT_DIR/test-data/canonical_build.canonical_build_artifacts/$JOB

export 'ANALYSIS_GRAPH_BOLT_URL=bolt://neo4j:artiphishell@localhost:7687'

export 'FUNC_RESOLVER_URL=http://localhost:4033'

export 'PDT_AGENT_URL=goaway'
export 'PDT_AGENT_SECRET=noway'

PROFILE=""
#PROFILE="py-spy record --format speedscope -o $SCRIPT_DIR/test-data/code-swipe-speedscope.json -- "

# Base arguments that apply to both modes
BASE_ARGS=" \
    --project-id $JOB \
    --project-metadata-path $(pwd)/test-data/analyze_target.metadata_path/$JOB.yaml \
    --project-dir $TARGET_DIR/ \
    --index-dir $(pwd)/test-data/generate_full_function_index.target_functions_index/$JOB \
    --index-dir-json $(pwd)/test-data/generate_full_function_index.target_functions_jsons_dir/$JOB \
    --output-path $(pwd)/test-data/output.yaml \
"

# Regular reports (used in both modes)
REGULAR_REPORTS_ARG=" \
    --codeql-cwe-report $(pwd)/test-data/codeql_cwe_queries.codeql_cwe_report/$JOB \
    --semgrep-report-path $(pwd)/test-data/semgrep_analysis.semgrep_analysis_report/$JOB \
"

DIFFGUY_REPORT_ARG=""
COMMIT_FUNCTIONS_ARG=""
BASE_REPORTS_ARG=""
CODEQL_DISCOVERY_ARG=""

if [ "$MODE" = "delta" ]; then
    DIFFGUY_REPORT_ARG="--diffguy-report-dir $(pwd)/test-data/diffguy.diffguy_reports/$PROJECT_NAME"
    COMMIT_FUNCTIONS_ARG=" \
        --commit-functions-index $(pwd)/test-data/generate_commit_function_index.target_functions_index/$JOB \
        --commit-functions-json $(pwd)/test-data/generate_commit_function_index.target_functions_jsons_dir/$JOB \
    "
    # Add base reports for delta mode (these will have negative weights)
    BASE_REPORTS_ARG=" \
        --codeql-cwe-report-base-path $(pwd)/test-data/codeql_cwe_queries_base.codeql_cwe_report_base/$JOB \
        --semgrep-report-base-path $(pwd)/test-data/semgrep_analysis_base.semgrep_analysis_report_base/$JOB \
        --scanguy-results-path $(pwd)/test-data/scan_guy_delta.scan_guy_results/$JOB \
    "
elif [ "$MODE" = "full" ]; then
    # Add discovery vuln reports for full mode only
    CODEQL_DISCOVERY_ARG="--codeql-report $(pwd)/test-data/quickseed_codeql_query.discovery_vuln_reports/$JOB" 
    BASE_REPORTS_ARG="\
        --scanguy-results-path $(pwd)/test-data/scan_guy_full.scan_guy_results/$JOB \
    "
fi

echo "MODE: $MODE"
echo "DIFFGUY_REPORT_ARG: $DIFFGUY_REPORT_ARG"
echo "BASE_REPORTS_ARG: $BASE_REPORTS_ARG"
echo "REGULAR_REPORTS_ARG: $REGULAR_REPORTS_ARG"

$PROFILE python3 ./src/main.py \
    $BASE_ARGS \
    $REGULAR_REPORTS_ARG \
    $DIFFGUY_REPORT_ARG \
    $COMMIT_FUNCTIONS_ARG \
    $BASE_REPORTS_ARG \
    $CODEQL_DISCOVERY_ARG
    # --scanguy-results-path $(pwd)/test-data/scanguy-results/
