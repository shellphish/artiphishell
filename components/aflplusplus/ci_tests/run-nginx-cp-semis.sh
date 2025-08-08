#!/bin/bash
# set -x
cd ci_tests/target-fuzz-common/

DURATION="${DURATION:-600}"
./run.sh https://github.com/aixcc-public/challenge-004-nginx-cp.git challenge-004-nginx-cp-semis "$DURATION"