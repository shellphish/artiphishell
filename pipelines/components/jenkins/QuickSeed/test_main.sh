set -x

BASE_DIR=$(dirname "$(realpath "$0")")
TEST_REL="tests/resource"
TEST=$(realpath "$BASE_DIR/$TEST_REL")
BENIGN_OUTPUT="/tmp/here/benign"
CRASH_OUTPUT="/tmp/here/crash"
mkdir -p ${BENIGN_OUTPUT}
mkdir -p ${CRASH_OUTPUT}


QuickSeed \
  --target $TEST/../target/targets-semis-aixcc-sc-challenge-002-jenkins-cp/ \
  --func-dir $TEST/json_output_dirs \
  --func-index $TEST/function_indices.json \
  --benign-dir ${BENIGN_OUTPUT} \
  --crash-dir ${CRASH_OUTPUT} \
  --report $TEST/codeql_report.yaml \
  --target-root $TEST/../target/targets-semis-aixcc-sc-challenge-002-jenkins-cp \
# --coverage-dir test_features/quickseed/resources/coverage_reports/ 
