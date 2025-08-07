#!/bin/bash

# prepare the test data

echo prepare
SCRIPT_DIR=$(dirname -- "$(realpath -- "$0")")
PARENT_DIR=$(dirname -- "$(realpath -- "$SCRIPT_DIR")")

echo ${SCRIPT_DIR}
echo ${PARENT_DIR}

OUTPUT_FILE_NAME=example_output.yaml
OUTPUT_FILE=${SCRIPT_DIR}/${OUTPUT_FILE_NAME}

touch ${OUTPUT_FILE}

tar xzf ${SCRIPT_DIR}/test_data.tar.gz -C ${SCRIPT_DIR}

cd ${PARENT_DIR}

echo building

# build the container
docker build -f ${SCRIPT_DIR}/Dockerfile.test -t aixcc-clang-indexer-diff-rank-test .

echo running

# run the command
docker run --rm \
    --name aixcc-clang-indexer-1 \
    -v ${SCRIPT_DIR}/test_data/clang_index_by_commit.output_dir:/commits_dir \
    -v ${SCRIPT_DIR}/test_data/targets-semis-aixcc-sc-challenge-004-nginx-cp:/target_dir \
    -v ${OUTPUT_FILE}:/${OUTPUT_FILE_NAME} \
    aixcc-clang-indexer-diff-rank-test \
    diff-ranker \
    -i /commits_dir \
    -d /target_dir \
    -o /${OUTPUT_FILE_NAME}
    
echo print

# print the results
yq . ${OUTPUT_FILE}

# cleanup

echo cleanup
rm -rf ${SCRIPT_DIR}/test_data
# rm -f ${OUTPUT_FILE}

docker rmi aixcc-clang-indexer-diff-rank-test
