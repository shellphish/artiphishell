#!/bin/bash

#shellcheck disable=SC2086

succeed() {
	# use when the build succeeds
	echo "$@"
	exit 0
}

fail() {
	# use when compilation error occurs
	warn "$1"
	exit 202
}

warn() {
	echo "$*" >&2
}

die() {
	# use when script error occurs
	warn "$*"
	exit 201
}

VERSION="v1.8.0"
print_ver() {
	echo "$VERSION"
}

print_usage() {
	echo "usage: build_cr [OPTION] -p PROJECT_NAME -r LOCAL_PROJ_REPO -o LOCAL_OSS_FUZZ_REPO

Options:
    -h                        show usage
    -v                        list current version
    -l LOCALE                 set the locale to use within the containers (deprecated)
    -s SANITIZER              set sanitizer for build 
                              {address,none,memory,undefined,thread,coverage,introspector,hwaddress}
                              the default is address
    -a ARCHITECTURE           set arch for build {i386,x86_64,aarch64}
    -d IMAGE_TAG              set the project docker image tag (default: latest)
    -e PROPAGATE_EXIT_CODE    propagate exit code from helper.py

Exit Codes:
    0       build_image, build_fuzzers, and check_build passed on all harnesses
    201     an error occured during the build step, likely runtime or scripting error
    202     a failure occured during the build step, likely compilation error
"
}

build_challenge_repository() {

	pushd "${LOCAL_OSS_FUZZ_REPO}" >/dev/null || die

	DOCKER_IMAGETAG_ARG=${IMAGE_TAG:+"--docker_image_tag ${IMAGE_TAG}"}
	PROPAGATE_EXIT_CODE_ARG=${PROPAGATE_EXIT_CODE:+"--propagate_exit_codes --err_result 201"}

	## A CRS patch submission cannot affect this step, so failing here is error (die 201)
	${PYTHON} infra/helper.py build_image --pull \
		--architecture "${ARCHITECTURE}" \
		${DOCKER_IMAGETAG_ARG} \
		${PROPAGATE_EXIT_CODE_ARG} \
		"${PROJECT_NAME}" || die "Failed to build the Docker image"

	## A CRS patch submission will affect this step, so failing here needs parsed
	set +e
	${PYTHON} infra/helper.py build_fuzzers --clean \
		--architecture "${ARCHITECTURE}" \
		--sanitizer "${SANITIZER}" \
		${DOCKER_IMAGETAG_ARG} \
		${PROPAGATE_EXIT_CODE_ARG} \
		"${PROJECT_NAME}" "${MY_LOCAL_PROJ_REPO}"
	BUILD_FUZZERS_EXIT=${PIPESTATUS[0]}
	set -e

	# whitelist known errors to error not failure
	case "${BUILD_FUZZERS_EXIT}" in
	0)
		echo "Build fuzzers succeeded."
		;;
	125 | 126 | 127 | 137 | 201)
		die "Build fuzzers failed with Docker error."
		;;
	*)
		fail "Build fuzzers failed. Likely compilation failure."
		;;
	esac

	## A CRS patch submission will affect this step, so we fail
	${PYTHON} infra/helper.py check_build \
		${PROPAGATE_EXIT_CODE_ARG} \
		--architecture "${ARCHITECTURE}" \
		--sanitizer "${SANITIZER}" \
		"${PROJECT_NAME}" || fail "Built harnesses failed to pass build check"

	popd >/dev/null || die

	succeed "Successfully built"
}

while getopts ":p:r:o:s:a:d:l:hve" opt; do
	case ${opt} in
	h)
		print_usage
		exit 0
		;;
	v)
		print_ver
		exit 0
		;;
	e)
		PROPAGATE_EXIT_CODE=1
		;;
	p)
		PROJECT_NAME="${OPTARG}"
		;;
	r)
		LOCAL_PROJ_REPO="${OPTARG}"
		;;
	o)
		LOCAL_OSS_FUZZ_REPO="${OPTARG}"
		;;
	s)
		SANITIZER="${OPTARG}"
		;;
	a)
		ARCHITECTURE="${OPTARG}"
		;;
	d)
		IMAGE_TAG="${OPTARG}"
		;;
	l)
		echo "locale flag is deprecated, doing nothing with its input."
		;;
	:)
		echo "Option -${OPTARG} requires an argument."
		exit 1
		;;
	?)
		echo "Invalid option: -${OPTARG}."
		exit 1
		;;
	esac
done

[ -z ${PROJECT_NAME+x} ] && print_usage && die "Must specify project name with -p"
[ -z ${LOCAL_PROJ_REPO+x} ] && print_usage && die "Must specify local project repo with -r"
[ -z ${LOCAL_OSS_FUZZ_REPO+x} ] && print_usage && die "Must specify local oss-fuzz repo with -o"

if [ ! -d "${LOCAL_PROJ_REPO}" ]; then
	die "LOCAL_PROJ_REPO does not exist: ${LOCAL_PROJ_REPO}"
fi

if [ ! -d "${LOCAL_OSS_FUZZ_REPO}" ]; then
	die "LOCAL_OSS_FUZZ_REPO does not exist: ${LOCAL_OSS_FUZZ_REPO}"
fi

# set default values if null is provided from github action
[ "${SANITIZER}" == "null" ] && SANITIZER="address"
[ "${ARCHITECTURE}" == "null" ] && ARCHITECTURE="x86_64"
[ "${IMAGE_TAG}" == "null" ] && IMAGE_TAG="latest"

# set defaults
# note, *not* setting IMAGE_TAG default
: "${PYTHON:="python3"}"
: "${SANITIZER:="address"}"
: "${ARCHITECTURE:="x86_64"}"

MY_LOCAL_PROJ_REPO=$(realpath "$LOCAL_PROJ_REPO")

build_challenge_repository

## leave these here in case a case is improperly handled
# shellcheck disable=SC2317
print_usage
# shellcheck disable=SC2317
exit 1
