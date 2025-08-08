#!/bin/bash

set -x
cd ci_tests/target-fuzz-common

DURATION="${DURATION:-960}"
./run.sh id_2 https://github.com/shellphish-support-syndicate/targets-semis-harden-demo3 harden-demo3
