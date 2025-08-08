#!/bin/bash

set -x
cd ci_tests/tests-common

DURATION="${DURATION:-600}"
./run.sh pipeline_poiguy_kasan.yaml
