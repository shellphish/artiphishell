#!/bin/bash

set -ex

export PATH=/root/.cargo/bin:$PATH

usage () {
    echo "Usage: $0 -b <benign_inputs_dir> -o <crashing_inputs_dir> -u <benign_coverage_dir> -z <crash_input_dir> -x <crash_coverage_dir> -y <benign_coverage_dir> -j <JOB_ID_REPLICAID>[ -f <kcov_filter_file> ]"
    exit 1
}

# Initialize variables that will hold the command line arguments
NPROC_VAL=${NPROC_VAL:=4}
JOB_ID_REPLICAID=${JOB_ID_REPLICAID:="1337"}
kcov_filter_file=""
benign_inputs_dir="/workdir/benign"
crashing_inputs_dir="/workdir/crashing"
benign_coverage_dir="/workdir/benign_coverage"
crash_coverage_dir="/workdir/crashing_coverage"

# Parse options with getopts in a loop
while getopts ":b:o:f:x:y:j:" opt; do
  case $opt in
    b)
      benign_inputs_dir=$OPTARG
      ;;
    y)
      benign_coverage_dir=$OPTARG
      ;;
    x)
      crash_coverage_dir=$OPTARG
      ;;
    o)
      crashing_inputs_dir=$OPTARG
      ;;
    f)
      kcov_filter_file=$OPTARG
      ;;
    j)
      JOB_ID_REPLICAID=$OPTARG
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      usage
      ;;
    :)
      echo "Option -$OPTARG requires an argument." >&2
      usage
      ;;
  esac
done

if [ -z "$benign_inputs_dir" ]; then
    echo "Need benign inputs directory"
    exit 1
elif [ -z "$crashing_inputs_dir" ]; then
    echo "Need crashing inputs directory"
    exit 1
elif [ -z "$benign_coverage_dir" ]; then
    echo "Need benign coverage directory"
    exit 1
elif [ -z "$crash_coverage_dir" ]; then
    echo "Need crash coverage directory"
    exit 1
fi

mkdir -p "$benign_inputs_dir"
mkdir -p "$crashing_inputs_dir"
mkdir -p "$benign_coverage_dir"
mkdir -p "$crash_coverage_dir"

TARGET_DIR="/snapchange/fuzzer"

# Test the fuzzer
# echo "[*] Testing fuzzer"
# pushd "$TARGET_DIR" || exit
# ./target/release/fuzzer_template project translate
# popd || exit

SEEDS_DIR="/snapchange/fuzzer/inputs"
mkdir -p "${SEEDS_DIR}"
echo "0000 0000 0101 0101 0202 0202" | xxd -p -r > "${SEEDS_DIR}/fuzz"
echo -n "FUZZ" > "${SEEDS_DIR}/godseed"
cp /snapchange_modifications/tipc_crasher.bin "${SEEDS_DIR}/tipc" || true

echo "$PATH"

echo "[*] Ready to rock'n'roll"
pushd "$TARGET_DIR" || exit
if [ -f "$kcov_filter_file" ]; then
  KCOV_FILE="$(realpath $kcov_filter_file)"
  cargo run -r -- fuzz \
    --cores "$NPROC_VAL" \
    -i "$SEEDS_DIR" \
    -b "$benign_inputs_dir" \
    -o "$crashing_inputs_dir" \
    -k "$KCOV_FILE" \
    -x "$crash_coverage_dir" \
    -y "$benign_coverage_dir" \
    -j "$JOB_ID_REPLICAID" \
    --ascii-stats 2>&1 | tee /workdir/log
else
  cargo run -r -- fuzz \
    --cores "$NPROC_VAL" \
    -i "$SEEDS_DIR" \
    -b "$benign_inputs_dir" \
    -o "$crashing_inputs_dir" \
    -y "$benign_coverage_dir" \
    -x "$crash_coverage_dir" \
    -j "$JOB_ID_REPLICAID" \
    --ascii-stats 2>&1 | tee /workdir/log
fi
popd || exit
