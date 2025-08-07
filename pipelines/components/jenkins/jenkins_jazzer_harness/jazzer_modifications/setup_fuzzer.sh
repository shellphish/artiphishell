#!/bin/sh
# This file is meant to be sourced by the pipeline task

FOO=$(yq ".harnesses.${CP_HARNESS_ID}" project.yaml || true)
if test "$FOO" = "null"; then
  echo "${CP_HARNESS_ID} is not a valid harness ID"
  exit 1
fi

set +x

# jq -r '.["#select"].tuples[][] | gsub("\\n"; "") | walk(
# if type == "string" then
#   if (gsub("\u0000"; "") | length) == 0 then
#     ""
#   else
#     .
#   end
# else
#   .
# end
# ) | select(length > 0) | @base64' "${CODEQL_FILE}" | while read -r line; do echo "\"$(echo $line | base64 -d)\""; done > ./dict.txt

set -x

RAND="$(head /dev/urandom -c 5 | xxd -p | tr -d '\n')"

# new format
cp /jazzer_modifications/Dockerfile.extensions .
BASE_IMAGE="$(yq -r '.docker_image' ./project.yaml)"
export DOCKER_IMAGE_NAME="aixcc-jazzer-${TARGET_ID}-${RAND}"
export DOCKERFILE_PATH="Dockerfile.extensions"


mkdir -p "${INSTANCE_DIR}/work"

touch "${INSTANCE_DIR}/work/empty_codeql.yaml"

# jazzer needs jazzer strings
cp /jazzer_modifications/jazzer_strings.txt .
cp /jazzer_modifications/find_instrumentation.py .
python3 find_instrumentation.py --func_report="${FUNC_INDEXER_REPORT}" --packages_in_scope="${INSTANCE_DIR}/work/packages_in_scope.json" --reachability_report="${CODEQL_FILE}"
cp /jazzer_modifications/auto_kill.sh "${INSTANCE_DIR}/work"

while read -r line; do echo "$line" >> dict.txt; done < jazzer_strings.txt
cp /jazzer_modifications/jazzer_wrapper.py .
# cp packages_in_scope.txt "${INSTANCE_DIR}/work/packages_in_scope.txt"
cp /jazzer_modifications/jazzer_fuzzing_configs.yaml "${INSTANCE_DIR}/work"
# python3 find_instrumentation.py --func_report=${FUNC_INDEXER_REPORT} --packages_in_scope="${INSTANCE_DIR}/work/packages_in_scope.json" --reachability_report="${REACHABILITY_RESULT}"
docker build --build-arg=BASE_IMAGE="${BASE_IMAGE}" -t "${DOCKER_IMAGE_NAME}" -f "$DOCKERFILE_PATH" .

## Modify harness to enable fuzzing
## Get the harness file location
export HARNESS_FILE="$(yq ".harnesses.${CP_HARNESS_ID}.source" ./project.yaml | tr -d '"')"
export CP_HARNESS_NAME="$(yq ".harnesses.${CP_HARNESS_ID}.name" ./project.yaml | tr -d '"')"
          
## Docker doesn't like symlinks
## So we need to create a directory in /shared to be mounted into the container
## And then sync it with the crashing and benign inputs using inotifywait and rsync
export CONTAINER_INPUTS="${INSTANCE_DIR}/benign_harness_inputs"
export CONTAINER_OUTPUTS="${INSTANCE_DIR}/crashing_harness_inputs"
export CONTAINER_REPORTS="${INSTANCE_DIR}/crash_reports"
export CONTAINER_WORKDIR="${INSTANCE_DIR}/work"
mkdir -p "$CONTAINER_INPUTS" "$CONTAINER_OUTPUTS" "$CONTAINER_WORKDIR" "$CONTAINER_REPORTS"

set +x
echo
echo
echo
echo "========= Initializing Fuzzer via Wrapper ========"
set -x

## Benign input
echo "foo" > /tmp/foo

sed -i '/FUZZ_INDEX/d' "$INSTANCE_DIR/.env.docker"

## This should create the fuzz.sh and triage.sh in the work directory
# echo "running run_pov" >> jazzer1.log
# sleep 100m
./run.sh run_pov /tmp/foo "${CP_HARNESS_NAME}" | tee jazzer.log
# sleep 100m


set +x
echo
echo
echo
echo "========= Fuzzer Setup Complete ========"
echo
echo
echo

local_sync() {
    echo
    echo
    echo
    echo "========= Syncing Local Harness Inputs =========="
    echo "Syncing harness inputs"
    rsync -ra "${CONTAINER_INPUTS}/" \
        "/shared/${FUZZ_OUTPUT_DIR_REL}/benign_harness_inputs/" || true
    rsync -ra --exclude 'timeout*' --exclude 'slow*' "${CONTAINER_OUTPUTS}/" \
        "/shared/${FUZZ_OUTPUT_DIR_REL}/crashing_harness_inputs/" || true
    
    rsync -ra "/shared/${FUZZ_OUTPUT_DIR_REL}/benign_harness_inputs/" \
        "${CONTAINER_INPUTS}/" || true
    rsync -ra "/shared/${FUZZ_OUTPUT_DIR_REL}/crashing_harness_inputs/" \
        "${CONTAINER_OUTPUTS}/" || true
}

local_sync
