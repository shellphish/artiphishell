#!/bin/bash

#set -x

#shellcheck disable=SC2086

warn() {
	echo "$*" >&2
}

die() {
	# use when script failure occurs
	warn "$*"
	exit 201
}

succeed() {
	# use when our test succeeds as expected
	echo "$@"
	exit 0
}

fail() {
	# use when our test fails, but no error
	echo "$@"
	exit 202
}

VERSION="v3.1.1"
print_ver() {
	echo "$VERSION"
}

print_usage() {
	echo "usage: run_pov [OPTION] -p PROJECT_NAME -o LOCAL_OSS_FUZZ_REPO -b BLOB_PATH -f FUZZ_HARNESS -e ENGINE -s SANITIZER

Options:
    -h                  show usage
    -v                  list current version
    -x                  CRASH_NOT_EXPECTED (we do not expect a crash)
    -n                  run reproduce with --not_privileged set (docker priv removed)
    -a ARCHITECTURE     set arch for reproduce {i386,x86_64,aarch64}
    -t TIMEOUT_SEC      override the default reproduce timeout in seconds (default: None)
"
}

run_pov() {
	STDOUT_FILE="/tmp/fuzzer_stdout.txt"
	STDERR_FILE="/tmp/fuzzer_stderr.txt"
	COMBINED_FILE="/tmp/fuzz.out"

	pushd "${LOCAL_OSS_FUZZ_REPO}" >/dev/null || die "Could not pushd"

	PRIVILEGED_FLAG=${RUN_NOT_PRIVILEGED:+--not_privileged}
	TIMEOUT_ARG=${TIMEOUT_SEC:+"--timeout ${TIMEOUT_SEC}"}

	set +e
	"${PYTHON}" infra/helper.py reproduce --architecture "${ARCHITECTURE}" \
		--propagate_exit_codes \
		${PRIVILEGED_FLAG} \
		${TIMEOUT_ARG} \
		--err_result 201 \
		"${PROJECT_NAME}" "${FUZZ_HARNESS}" "${BLOB_ABS}" \
		2> >(tee ${STDERR_FILE} >&2) | tee ${STDOUT_FILE}
	REPRO_EXIT=${PIPESTATUS[0]}
	set -e

	cat "${STDOUT_FILE}" >${COMBINED_FILE}
	echo "" >>"${COMBINED_FILE}"
	cat "${STDERR_FILE}" >>${COMBINED_FILE}

	popd >/dev/null || die "Failed to popd"

	SCRIPT_PATH="$(readlink -f "$0")"
	SCRIPT_DIR="$(dirname "$SCRIPT_PATH")"
	CRASH_SCRIPT="${SCRIPT_DIR}/crash_interpret_config.py"
	CONFIG_FILE="${SCRIPT_DIR}/ossfuzz_config.yaml"

	# The Python script uses:
	# 0 => No significant crash recognized
	# 211 => Recognized sanitizer crash
	# 212 => Recognized non-sanitizer but notable crash
	# 213 => Recognized sanitizer signature despite return_code=0 (error)
	# 214 => Recognized error in reproducing
	set +e
	set -x
	PY_OUTPUT=$("${PYTHON}" "${CRASH_SCRIPT}" \
		--engine "${ENGINE}" \
		--sanitizer "${SANITIZER}" \
		--return_code "${REPRO_EXIT}" \
		--config_path "${CONFIG_FILE}" \
		--stderr_path "${STDERR_FILE}" \
		--stdout_path "${STDOUT_FILE}" 2>&1)
	SCRIPT_EXIT=$?
	set +x
	set -e

	case "${SCRIPT_EXIT}" in
	0 | 211 | 212 | 213 | 214)
		echo "Exit parsing script ran as expected."
		;;
	*)
		die "Running parsing script encountered an error!"
		;;
	esac

	echo "Interpreter script exit code = ${SCRIPT_EXIT}" >&2
	echo "Interpreter output:" >&2
	echo "${PY_OUTPUT}" >&2

	# If CRASH_NOT_EXPECTED=1, we do NOT expect a crash
	# else, we DO expect a crash

	case "${SCRIPT_EXIT}" in
	0)
		if [ -n "${CRASH_NOT_EXPECTED:-}" ]; then
			succeed "No crash, as expected" >&2
		else
			fail "No crash recognized (but expected one)!" >&2
		fi
		;;
	211)
		if [ -n "${CRASH_NOT_EXPECTED:-}" ]; then
			fail "Sanitizer crash occurred, but was not expected!" >&2
		else
			succeed "Sanitizer crash occurred, and crash was expected!" >&2
		fi
		;;
	212)
		if [ -n "${CRASH_NOT_EXPECTED:-}" ]; then
			fail "Notable non-sanitizer (or Jazzer) crash occurred, but was not expected!" >&2
		else
			succeed "Notable non-sanitizer (or Jazzer) crash occurred, and crash was expected!" >&2
		fi
		;;
	213)
		die "ERROR: Recognized sanitizer signature despite no crash code caught!" >&2
		;;
	214)
		die "ERROR: Reproduce error: $(cat "${STDERR_FILE}")" >&2
		;;
	*)
		die "Error: Something went wrong: $(cat "${STDERR_FILE}")" >&2
		;;
	esac

}

while getopts ":p:o:a:b:f:e:s:t:hvxn" opt; do
	case ${opt} in
	h)
		print_usage
		exit 0
		;;
	v)
		print_ver
		exit 0
		;;
	x)
		CRASH_NOT_EXPECTED=1
		;;
	n)
		RUN_NOT_PRIVILEGED=1
		;;
	p)
		PROJECT_NAME="${OPTARG}"
		;;
	o)
		LOCAL_OSS_FUZZ_REPO="${OPTARG}"
		;;
	a)
		ARCHITECTURE="${OPTARG}"
		;;
	b)
		BLOB_PATH="${OPTARG}"
		;;
	f)
		FUZZ_HARNESS="${OPTARG}"
		;;
	e)
		ENGINE="${OPTARG}"
		;;
	s)
		SANITIZER="${OPTARG}"
		;;
	t)
		TIMEOUT_SEC="${OPTARG}"
		;;
	:)
		print_usage && die "Option -${OPTARG} requires an argument."
		;;
	?)
		print_usage && die "Invalid option: -${OPTARG}."
		;;
	esac
done

[ -z ${PROJECT_NAME+x} ] && print_usage && die "Must specify project name with -p"
[ -z ${LOCAL_OSS_FUZZ_REPO+x} ] && print_usage && die "Must specify local oss-fuzz repo with -o"
[ -z ${BLOB_PATH+x} ] && print_usage && die "Must specify blob with -b"
[ -z ${FUZZ_HARNESS+x} ] && print_usage && die "Must specify fuzz harness with -f"
[ -z ${ENGINE+x} ] && print_usage && die "Must specify engine used to build fuzz harness with -e"
[ -z ${SANITIZER+x} ] && print_usage && die "Must specify sanitizer used to build fuzz harness with -s"

# set default values if null is provided from github action
[ "${ENGINE}" == "null" ] && ENGINE="libfuzzer"
[ "${SANITIZER}" == "null" ] && SANITIZER="address"
[ "${ARCHITECTURE}" == "null" ] && ARCHITECTURE="x86_64"

# set other defaults
# note: *not* defaulting TIMEOUT_SEC to keep it backwards compatible with oss-fuzz-aixcc v1.1.0
: "${PYTHON:="python3"}"
: "${ARCHITECTURE:="x86_64"}"

# Check if the specified paths exist:
if [ ! -d "${LOCAL_OSS_FUZZ_REPO}" ]; then
	die "LOCAL_OSS_FUZZ_REPO does not exist: ${LOCAL_OSS_FUZZ_REPO}"
fi

if [ ! -e "${BLOB_PATH}" ]; then
	die "BLOB_PATH does not exist: ${BLOB_PATH}"
fi

BLOB_ABS=$(realpath "${BLOB_PATH}")

run_pov
