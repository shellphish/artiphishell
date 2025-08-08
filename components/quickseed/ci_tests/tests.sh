#!/bin/bash

set -ex

# Install dependencies

sudo apt-get update -y && sudo apt-get install -y git unzip tar graphviz xdg-utils
python -m pip install --upgrade pip
pip install -e .

export CODEQL_SERVER_URL='http://localhost:4000'
# export ANALYSIS_GRAPH_BOLT_URL='bolt://neo4j:helloworldpdt@localhost:7687'
export AGENTLIB_SAVE_FILES=0
export LITELLM_KEY='sk-artiphishell-da-best!!!'
export AIXCC_LITELLM_HOSTNAME="http://wiseau.seclab.cs.ucsb.edu:666"
export USE_LLM_API=1
export PROJECT_DIR=./tests/targets/mock-cp-java/mock-cp-java/

export SHARED_WORKDIR=/shared/ci_tests/quickseed/
export FUZZ_SYNC_DIR=/shared/fuzzer_sync/
sudo mkdir -p $SHARED_WORKDIR
sudo mkdir -p $FUZZ_SYNC_DIR
sudo chown -R $(id -u):$(id -g) $SHARED_WORKDIR
sudo chown -R $(id -u):$(id -g) $FUZZ_SYNC_DIR
export DEBUG_BUILD=$SHARED_WORKDIR/debug_build/
export COVERAGE_BUILD=$SHARED_WORKDIR/coverage_build/
export QUICKSEED_DO_NOT_REBUILD_COVERAGE_IMAGE=1
mkdir -p $DEBUG_BUILD
mkdir -p $COVERAGE_BUILD

# Set up oss-fuzz base-runner
docker pull ghcr.io/aixcc-finals/base-runner:v1.2.0
docker pull ghcr.io/shellphish-support-syndicate/shellphish-oss-fuzz-runner-shellphish-mock-cp-java--coverage_fast
docker tag ghcr.io/shellphish-support-syndicate/shellphish-oss-fuzz-runner-shellphish-mock-cp-java--coverage_fast shellphish-oss-fuzz-runner-mock-cp-java--coverage_fast
oss-fuzz-build-image ./tests/targets/mock-cp-java/mock-cp-java --instrumentation libfuzzer --build-runner-image
# Set up codeql client

pushd ../../services/codeql_server
    docker-compose up -d --force-recreate --no-deps --remove-orphans
    # Add a restart policy update to ensure it doesn't restart
    docker update --restart=no $(docker-compose ps -q)
    sleep 10
popd
# # upload codeql database
codeql-upload-db  --cp_name mock-cp-java --project_id 1 --language java --db_file ./tests/targets/mock-cp-java/codeql-database.tar.gz
# # set up analysis graph
# pushd ../../services/analysis_graph
#     docker-compose up -d --force-recreate --no-deps --remove-orphans
#     # Add a restart policy update to ensure it doesn't restart
#     docker update --restart=no $(docker-compose ps -q)
#     sleep 10
# popd

pushd ../../libs/libcodeql
    pip install -e .
popd

# pushd ../../libs/analysis-graph
#     pip install -e .
# popd


# Pytest
export ON_CI=true
export LOG_LEVEL=info
export LOG_LLM=1

export CRASH_DIR_PASS_TO_POV=$(mktemp -d /tmp/crash_dir_pass_to_pov.XXXXXX)
export CRASH_METADATA_DIR_PASS_TO_POV=$(mktemp -d /tmp/crash_metadata_dir_pass_to_pov.XXXXXX)
# Prepare pintools since we are not running inside docker
mkdir -p ../../blobs
wget 'https://software.intel.com/sites/landingpage/pintool/downloads/pin-external-3.31-98869-gfa6f126a8-gcc-linux.tar.gz' -O ../../blobs/pin.tar.gz
# Fetch the debug build and coverage build
wget -O "$SHARED_WORKDIR/coverage_build.tar.gz" 'https://www.dropbox.com/scl/fi/8efhfhj53mqdbk3flxw0h/coverage_build_artifacts.tar.gz?rlkey=hj85rrjg9cewqx0x3lbyr5f0j&st=72cw65xr&dl=1' 
file "$SHARED_WORKDIR/coverage_build.tar.gz"
tar -xf $SHARED_WORKDIR/coverage_build.tar.gz -C $SHARED_WORKDIR/coverage_build/
wget -O "$SHARED_WORKDIR/debug_build.tar.gz" 'https://www.dropbox.com/scl/fi/76dgt4ebgg0d96k0q4b96/debug_build_artifacts.tar.gz?rlkey=4lxf9bmm2s3d0gbtz38jnx2lw&st=u9p0dbjh&dl=1'
tar -xf $SHARED_WORKDIR/debug_build.tar.gz -C $SHARED_WORKDIR/debug_build/

sudo chown -R $(id -u):$(id -g) ../../libs/
sudo chown -R $(id -u):$(id -g) /shared
# Find your Python interpreter
export QUICKSEED_PATH=$(which QuickSeed)
export QUICKSEED_LLM_MODEL="gpt-4.1-nano" # Use this one for saving money
PYTHON_PATH=$(which python)
# Run pytest with that interpreter
sudo -E $PYTHON_PATH -m pytest --log-cli-level=DEBUG --log-level=DEBUG -s -v ./tests/tests.py
# sudo -E $(which pytest) --log-cli-level=DEBUG --log-level=DEBUG -s -v ./tests/tests.py
PYTEST_EXIT_CODE=$?

docker kill aixcc-codeql-server || true
docker rm aixcc-codeql-server || true
# docker kill aixcc-analysis-graph || true
# docker rm aixcc-analysis-graph || true
sudo chown -R $(id -u):$(id -g) ../../services/codeql_server # Reset permissions
# sudo chown -R $(id -u):$(id -g) ../../services/analysis_graph # Reset permissions
sudo chown -R $(id -u):$(id -g) $SHARED_WORKDIR 
exit $PYTEST_EXIT_CODE