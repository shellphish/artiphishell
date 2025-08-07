#!/bin/bash
#
# FIXME Change so that absolute path is given to program. No more internal dependencies
export OPENAI_API_KEY="$(cat $(realpath ../openai.key))"
export GRAMMARDIR="$(realpath src/grammars/$1)"
export LOG_LLM=1 
export LOG_LEVEL=info

set -e

while getopts n:l:i:m:t:c: option
do
case "${option}"
in
n) export NUM_INPUTS=${OPTARG};;
l) export LINE=${OPTARG};;
i) export NUM_ITERATIONS=${OPTARG};;
m) export MODEL=${OPTARG};;
t) export TARGET=${OPTARG};;
c) export CLEAN=${OPTARG};;
esac
done

source activate ~/envs/thesis_fuzz/bin/activate
conc_flags=""

if [ -n "$TARGET" ]; then
    conc_flags+="-t ${TARGET} "
fi 

if [ -n "$CLEAN" ]; then
    conc_flags+="-c "
fi 

if [ -n "$NUM_INPUTS" ]; then
    conc_flags+="-n ${NUM_INPUTS} "
fi 

if [ -n "$LINE" ]; then
    conc_flags+="-l ${LINE} "
fi 

if [ -n "$MODEL" ]; then
    conc_flags+="-m ${MODEL} "
fi

if [ -n "$NUM_ITERATIONS" ]; then
    conc_flags+="-i ${NUM_ITERATIONS}"
fi 

echo "CONC FLAGS ${conc_flags}"

python3 src/spearfuzz/grammar-guy.py ${conc_flags}