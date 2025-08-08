# Challenge Evaluation Scripts

This repository contains scripts used in the processing of Challenge Repositories,
PoVs, and Patches. These scripts provide the ability to build and check the repository,
run povs, apply patches, and run functional test scripts for given repositories in the
same way they are run in the competition evaluation.

## What's Inside

This set contains three primary scripts:

- `build_cr.sh`
- `run_pov.sh`
- `run_tests.sh`

### Build CR

```bash
usage: build_cr [OPTION] -p PROJECT_NAME -r LOCAL_PROJ_REPO -o LOCAL_OSS_FUZZ_REPO

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
```

The `build_cr.sh` script builds a target challenge repository's image and harnesses, and  
then checks the harness build state. It builds the local state of the challenge repository source  
passed by `-r LOCAL_PROJ_REPO`.

### Run PoV

```bash
usage: run_pov [OPTION] -p PROJECT_NAME -o LOCAL_OSS_FUZZ_REPO -b BLOB_PATH -f FUZZ_HARNESS -e ENGINE -s SANITIZER

Options:
    -h                  show usage
    -v                  list current version
    -x                  CRASH_NOT_EXPECTED (we do not expect a crash)
    -n                  run reproduce with --not_privileged set (docker priv removed)
    -a ARCHITECTURE     set arch for reproduce {i386,x86_64,aarch64}
    -t TIMEOUT_SEC      override the default reproduce timeout in seconds (default: None)
```

The `run_pov.sh` script runs a target pov blob against a target challenge repository harness, parses a  
combination of the process exit code and stdin and stdout contents to determine if a notable crash occurred.  
The challenge repository and harnesses must be built before `run_pov.sh` is invoked.

The script returns 0 if the expected behavior occurred, and non-zero otherwise. The expected behavior can  
be set with the `-x` flag (use `-x` when a crash is _not_ expected).

### Run Tests

```bash
usage: run_tests [OPTION] -p PROJECT_NAME -r LOCAL_PROJ_REPO

Options:
    -h                  show usage
    -v                  list current version
    -t TEST_SCRIPT      pass the test script to run (default .aixcc/test.sh)
    -i DOCKER_IMAGE     set docker image name (default aixcc-afc/<proj_name>)
                        overrides IMAGE_TAG
    -d IMAGE_TAG        set docker image tag (default: latest)
    -x                  set -x when success is not expected, this affects exit code
```

The `run_tests.sh` script runs the challenge repository test script (at `.aixcc/test.sh`) against the  
local state of the source code passed by `-r LOCAL_PROJ_REPO`. This runs the tests in an isolated  
environment as to not affect the state of the source on the host machine.

## Running the Scripts

Here are some examples of running these scripts on the sample integration-test challenge repository.

```bash
# clone the integration-test repository and oss-fuzz-aixcc repositories
git clone git@github.com:aixcc-finals/integration-test.git
git clone git@github.com:aixcc-finals/oss-fuzz-aixcc.git

# check out the challenge branch
git -C integration-test checkout challenges/integration-test-delta-01

# build the challenge
action-build-cr/build_cr.sh -p integration-test \
    -r ./integration-test \
    -o ./oss-fuzz-aixcc

# run the provided PoV (expecting a crash)
action-run-pov/run_pov.sh -n -p integration-test \
    -o ./oss-fuzz-aixcc \
    -b ./integration-test/.aixcc/vulns/vuln_001/blobs/blobs.bin \
    -f fuzz_vuln \
    -e libfuzzer \
    -s address \
    -t 1800

# apply the provided good patch
git -C integration-test apply .aixcc/vulns/vuln_001/patches/good-patch.diff

# re-build the challenge
action-build-cr/build_cr.sh -p integration-test \
    -r ./integration-test \
    -o ./oss-fuzz-aixcc

# re-run the provided PoV (not expecting a crash w/ -x)
action-run-pov/run_pov.sh -x -n -p integration-test \
    -o ./oss-fuzz-aixcc \
    -b ./integration-test/.aixcc/vulns/vuln_001/blobs/blobs.bin \
    -f fuzz_vuln \
    -e libfuzzer \
    -s address \
    -t 1800

# run functional tests provided with challenge
action-run-tests/run_tests.sh -p integration-test \
    -r ./integration-test
```
