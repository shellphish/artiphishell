#!/bin/bash
# set -x
cd ci_tests/target-fuzz-common/

export ONLY_HARNESSES="id_1 id_7 id_3"

DURATION="${DURATION:-600}"
./run.sh https://github.com/shellphish-support-syndicate/targets-semis-sqlite3 targets-semis-sqlite3 "$DURATION"
