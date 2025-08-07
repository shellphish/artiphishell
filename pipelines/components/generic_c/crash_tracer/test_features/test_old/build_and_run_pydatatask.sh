#!/usr/bin/bash

set -e
set -x

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
TARGETS_DIR="${TARGETS_DIR:-$SCRIPT_DIR/../../targets}"
pdl

set -x
pd inject buildguyASAN.target 1 < $TARGETS_DIR/CPP/hamlin/hamlin-pipeline-no-crc.tar.gz
pd inject asan2report.crash_input 5678 < $(dirname $0)/crash_input
cat <<EOF | pd inject asan2report.crash_metadata 5678
parent: "1"
EOF
cat <<EOF | pd inject asan2report.target_runtime_config 1
env: "CHESS=1"
args: ""
EOF


pd status

pd --verbose --fail-fast run
