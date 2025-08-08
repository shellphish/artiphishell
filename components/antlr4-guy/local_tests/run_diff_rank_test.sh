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

tar xzf ${SCRIPT_DIR}/antlr4_test_data.tar.gz -C ${SCRIPT_DIR}

cd ${PARENT_DIR}

echo building

# build the container
docker build -f ${SCRIPT_DIR}/Dockerfile.test -t aixcc-antlr4-diff-rank-test .

echo running

# run the command
docker run --rm \
    --name aixcc-antlr4-guy-1 \
    -v ${SCRIPT_DIR}/antlr4_test_data/antlr4_commit_java_parser.output_dir_java:/commits_dir \
    -v ${SCRIPT_DIR}/antlr4_test_data/./targets-semis-aixcc-sc-challenge-002-jenkins-cp:/target_dir \
    -v ${OUTPUT_FILE}:/${OUTPUT_FILE_NAME} \
    aixcc-antlr4-diff-rank-test \
    python /app/diff_ranker.py \
    -i /commits_dir \
    -d /target_dir \
    -o /${OUTPUT_FILE_NAME}
    
echo print

# print the results
yq . ${OUTPUT_FILE}

# cleanup

echo cleanup
rm -rf ${SCRIPT_DIR}/antlr4_test_data
# rm -f ${OUTPUT_FILE}

docker rmi aixcc-antlr4-diff-rank-test
