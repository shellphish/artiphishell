#!/bin/bash

# This performs the CP-specific build. It may be replaced with a script
# or binary for a different interpreter. The name MUST NOT change.

set -e
set -o pipefail

echo "###################YEEEEEET####################\n"

export CP_HARNESS_BUILD_PREFIX=""
/shellphish/codeql_build.py cmd_harness.sh build_final
