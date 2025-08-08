#!/bin/bash

set -x


ENGINE="$1"
SANITIZER="$2"
REPRO_EXIT="$3"
STDOUT_FILE="$4"
STDERR_FILE="$5"
OUTPUT_FILE="$6"


# set default values if null is provided from github action
[ "${ENGINE}" == "null" ] && ENGINE="libfuzzer"
[ "${SANITIZER}" == "null" ] && SANITIZER="address"
[ "${ARCHITECTURE}" == "null" ] && ARCHITECTURE="x86_64"

# set other defaults
: "${PYTHON:="python3"}"
: "${ARCHITECTURE:="x86_64"}"

COMBINED_FILE=$(mktemp /tmp/fuzz.out.XXXXXX)

cat "${STDOUT_FILE}" >${COMBINED_FILE}
echo "" >>"${COMBINED_FILE}"
cat "${STDERR_FILE}" >>${COMBINED_FILE}

SCRIPT_PATH="$(readlink -f "$0")"
SCRIPT_DIR="$(dirname "$SCRIPT_PATH")"
CRASH_SCRIPT="${SCRIPT_DIR}/example-challenge-evaluation/action-run-pov/crash_interpret_config.py"
CONFIG_FILE="${SCRIPT_DIR}/example-challenge-evaluation/action-run-pov/ossfuzz_config.yaml"

# The Python script uses:
# 0 => No significant crash recognized
# 211 => Recognized sanitizer crash
# 212 => Recognized non-sanitizer but notable crash
# 213 => Recognized sanitizer signature despite return_code=0 (error)
# 214 => Recognized error in reproducing
set +e
PY_OUTPUT=$("${PYTHON}" "${CRASH_SCRIPT}" \
	--config_path "${CONFIG_FILE}" \
	--engine "${ENGINE}" \
	--sanitizer "${SANITIZER}" \
	--return_code "${REPRO_EXIT}" \
	--stderr_path "${STDERR_FILE}" \
	--stdout_path "${STDOUT_FILE}" \
	--output_path "${OUTPUT_FILE}" \
	2>&1
)
SCRIPT_EXIT=$?
set -e
exit "${SCRIPT_EXIT}"