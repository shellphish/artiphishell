#!/bin/bash

# FIXME SET FROM INSIDE ONLY API KEY
export BASEDIR="/home/zebck/Documents/ucsb_work/"
export TARGET=$1
export RUNS=$2
export OPENAI_API_KEY="$(cat $(realpath ../openai.key))"

echo "$(cat $OPENAI_API_KEY)"

set -e 

pushd tools/grammarinator/
pip3 install -e .
popd 

if [ "$#" -ne 2 ] && [ "$#" -ne 3 ]; then
    echo "Usage: $0 <target> <num_inputs> optional <-q for quiet> <-s to show coverage report>"
    exit 1
fi

if [ -n "$3" ]; then
    echo 'Running in quiet mode';
    cd "${BASEDIR}/"work; ./cleanup.sh ${TARGET} >> /dev/null; ./generate_input.sh ${TARGET} ${RUNS} >> /dev/null;
    echo "generated inputs in sh";
    cd ../targets; ./collect_coverage.sh ${RUNS} ${TARGET} >> /dev/null; ./generate_coverage_report.sh ${TARGET} >> /dev/null;
else
    echo 'Running';
    cd "${BASEDIR}/"work; ./cleanup.sh ${TARGET}; ./generate_input.sh ${TARGET} ${RUNS};
    echo "generated inputs in sh";
    cd ../targets; ./collect_coverage.sh ${RUNS} ${TARGET}; ./generate_coverage_report.sh ${TARGET};
fi

echo "Done."