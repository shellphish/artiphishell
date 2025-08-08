#!/bin/bash

set -ex

export PATH=/root/.cargo/bin:$PATH

usage () {
    echo "Usage: $0 -o <output_dir> -j <JOB_ID_REPLICAID>[ -f <kcov_filter_file> ]"
    exit 1
}

# Initialize variables that will hold the command line arguments
NPROC_VAL=${NPROC_VAL:=4}
JOB_ID_REPLICAID=${JOB_ID_REPLICAID:="1337"}
kcov_filter_file=""
OUTPUT_DIR="/workdir/output"

# Parse options with getopts in a loop
while getopts ":o:f:j:" opt; do
  case $opt in
    o)
      OUTPUT_DIR=$OPTARG
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


mkdir -p "$OUTPUT_DIR"

TARGET_DIR="/snapchange/snapchange/fuzzer"

# Test the fuzzer
# echo "[*] Testing fuzzer"
# pushd "$TARGET_DIR" || exit
# ./target/release/fuzzer_template project translate
# popd || exit

SEEDS_DIR="/snapchange/snapchange/fuzzer/inputs"
mkdir -p "${SEEDS_DIR}"
# echo "0000 0000 0101 0101 0202 0202" | xxd -p -r > "${SEEDS_DIR}/fuzz"
# echo -n "FUZZ" > "${SEEDS_DIR}/godseed"
# cp /snapchange_modifications/tipc_crasher.bin "${SEEDS_DIR}/tipc" || true
echo "0100 0000 0000 0000 0000 0000" | xxd -p -r > "${SEEDS_DIR}/fsopen"
echo "0100 0000 0200 0000 0000 0000 0500 0000" | xxd -p -r > "${SEEDS_DIR}/fsconfig"
echo "0100 0000 0100 0000 0000 0000" | xxd -p -r > "${SEEDS_DIR}/close"

#echo "0xffffffff814a4d80,0xffffffff814a4efb" > /snapchange/fuzzer/syscall_sequence
#echo "0xffffffff814a5540,0xffffffff814a55ac" >> /snapchange/fuzzer/syscall_sequence
#echo "0xffffffff81421f90,0xffffffff81421ffe" >> /snapchange/fuzzer/syscall_sequence

# echo "$PATH"

echo "[*] Ready to rock'n'roll"
pushd "$TARGET_DIR" || exit
if [ -f "$kcov_filter_file" ]; then
  KCOV_FILE="$(realpath $kcov_filter_file)"
  cargo run -r -- fuzz \
    --cores "$NPROC_VAL" \
    -i "$SEEDS_DIR" \
    -o "$OUTPUT_DIR" \
    -k "$KCOV_FILE" \
    -j "$JOB_ID_REPLICAID" \
    --ascii-stats 2>&1 | tee /workdir/log
else
  cargo run -r -- fuzz \
    --cores "$NPROC_VAL" \
    -i "$SEEDS_DIR" \
    -o "$OUTPUT_DIR" \
    -j "$JOB_ID_REPLICAID" \
    --ascii-stats 2>&1 | tee /workdir/log
    #-s /snapchange/fuzzer/syscall_sequence \
fi
popd || exit
