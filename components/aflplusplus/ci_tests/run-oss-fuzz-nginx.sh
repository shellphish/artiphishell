#!/bin/bash
# set -x
cd ci_tests/oss-fuzz-common/

OSS_FUZZ_DIR="/aixcc-backups/oss-fuzz"
mkdir -p "$(dirname "$OSS_FUZZ_DIR")"
if [ ! -d "$OSS_FUZZ_DIR" ]; then
  git clone https://github.com/google/oss-fuzz.git "$OSS_FUZZ_DIR"
fi

DURATION="${DURATION:-600}"
./run.sh $OSS_FUZZ_DIR/projects/nginx http_request_fuzzer "$DURATION"
