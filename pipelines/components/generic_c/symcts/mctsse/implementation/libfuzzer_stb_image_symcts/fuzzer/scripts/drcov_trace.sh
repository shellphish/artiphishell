#!/bin/bash

export DRHOME=/home/honululu/lukas/tools/DynamoRIO-Linux-8.0.0-1/bin64

# Check if all required arguments are provided
if [ $# -ne 4 ]; then
    echo "Usage: $0 <binary> <testcase_dir> <output_dir> <afl_args>"
    exit 1
fi

# Assign arguments to variables
binary=$1
testcase_dir=$2
output_dir=$3
afl_args=$4

# Check if testcase directory exists
if [ ! -d "$testcase_dir" ]; then
    echo "Testcase directory does not exist, creating it..."
    mkdir -p "$testcase_dir"
fi

# Check if output directory exists, if not create it
if [ ! -d "$output_dir" ]; then
    mkdir -p "$output_dir"
fi

# Loop through all testcases
testcases=("$testcase_dir"/*)

#iterate over them by index
for i in `seq 1 ${#testcases[@]}`; do
    testcase="${testcases[$i-1]}"
    echo "############### ${i}/${#testcases[@]}: $testcase"
    # Run drcov on the testcase
    if [[ "$afl_args" == *@@* ]]; then
        # Replace @@ with the testcase filepath
        afl_args="${afl_args/@@/$testcase}"
        "$DRHOME/drrun" -t drcov -dump_binary -dump_text -logdir "$output_dir" -logprefix "cov_$(basename $testcase)" -- "$binary" $afl_args
    else
        # Use stdin to pass the testcase
        "$DRHOME/drrun" -t drcov -dump_binary -dump_text -logdir "$output_dir" -logprefix "cov_$(basename $testcase)" -- "$binary" $afl_args < "$testcase"
    fi
    echo; echo; echo;
done
