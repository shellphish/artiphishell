#!/bin/bash
# set -x
cd ci_tests/target-fuzz-common/

DURATION="${DURATION:-300}"
./run.sh https://github.com/shellphish-support-syndicate/targets-semis-aixcc-sc-mock-cp.git mock-cp "$DURATION"