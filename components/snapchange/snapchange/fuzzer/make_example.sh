#!/bin/bash

set -x

VM_LOG_FILE=/snapchange/snapchange/fuzzer/vm.log
CUR_DIR=$(dirname $(realpath $0))
BIN_FILE=$1
KERNEL_ROOT_DIR=$2

AMI=$1

# Add snapchange as dependency and build-dependency for this example
$HOME/.cargo/bin/cargo add snapchange --path /snapchange/snapchange


take_snapshot() {
  # Sanity check the target has been build
  if [ ! -f "$BIN_FILE" ]; then
    echo "ERROR: $BIN_FILE target not found"
    exit 0
  fi

  # Build the image to execute the harness on start
  echo "[+] Calling build.sh on $BIN_FILE"
  /snapchange/qemu_stuff/build.sh "$BIN_FILE"

  # Take the snapshot
  echo "[+] Calling snapshot.sh"
  /snapchange/qemu_stuff/snapshot.sh "$KERNEL_ROOT_DIR"
}

# Move the snapshot directory out of qemu_snapshot
copy_snapshot_directory() {
  mv /snapchange/snapchange/fuzzer/output /snapchange/snapchange/fuzzer/snapshot
}

# Initialize the fuzzer based on the output of the snapshot
init_fuzzer() {
  # Check if fuzzer still has REPLACEME markers that need replacing
  grep REPLACEME src/fuzzer.rs >/dev/null

  # Continue replacing REPLACEME markers if they still exist
  if [ $? -eq 0 ]; then
    # Begin the fuzzer with the SNAPSHOT output from the vm.log
    COMMENTS=$(grep SNAPSHOT "$VM_LOG_FILE" | sed 's_^_// _g' | tr '\n' '\r')
    echo "Found snapshot comments in vm.log:"
    echo $COMMENTS

    # Slight hack to sed a multiline string
    sed -z "s_REPLACEMECOMMENTS_${COMMENTS}_" src/fuzzer.rs | tr '\r' '\n' > /tmp/.fuzzer.rs
    mv /tmp/.fuzzer.rs src/fuzzer.rs

    # Replace the RIP for the snapshot
    # RIP=0000000000401362 RFL=00000306 [-----P-] CPL=3 II=0 A20=1 SMM=0 HLT=0
    NEWRIP=$(grep RIP snapshot/*qemuregs | cut -d' ' -f1 | cut -d'=' -f2)
    if [ -z "$NEWRIP" ]; then
        echo "Error: No RIP found in snapshot files."
        exit 1
    fi
    echo "Found RIP in snapshot: $NEWRIP"
    sed  -i "s/REPLACEMERIP/0x${NEWRIP}/" src/fuzzer.rs

    # Replace the CR3 for the snapshot
    # 16:CR0=80050033 CR2=00007f8814613610 CR3=00000000084be000 CR4=000006f0
    NEWCR3=$(grep CR3 snapshot/*qemuregs | cut -d' ' -f3 | cut -d'=' -f2)
    echo "Found CR3 in snapshot: $NEWCR3"
    if [ -z "$NEWCR3" ]; then
        echo "Error: No CR3 found in snapshot files."
        exit 1
    fi
    sed -i "s/REPLACEMECR3/0x${NEWCR3}/" src/fuzzer.rs

    # Replace the data buffer from the snapshot
    # [   19.760751] rc.local[189]: SNAPSHOT Data buffer: 0x555555556004
    NEWBUFF=$(grep "Data buffer" "$VM_LOG_FILE" | rev | cut -d' ' -f1 | rev | tr -d '\r' | tr -d '\n')
    echo "Found data buffer in snapshot: $NEWBUFF"
    sed -i "s/REPLACEMEDATABUFFER/${NEWBUFF}/" src/fuzzer.rs

    KCOV_BUFF=$(grep "KCOV buffer" "$VM_LOG_FILE" | rev | cut -d' ' -f1 | rev | tr -d '\r' | tr -d '\n')
    echo "Found kcov buffer in snapshot: $KCOV_BUFF"
    sed -i "s/REPLACEMEKCOV/${KCOV_BUFF}/" src/fuzzer.rs

    LINE=$(grep "EDGE buffer" "$VM_LOG_FILE" | rev | cut -d' ' -f1 | rev)
    echo "Found coverage buffer in snapshot: $LINE"
    START=$(cut -d'-' -f1 <<< "$LINE")
    STOP=$(cut -d'-' -f2 <<< "$LINE")
    sed -i "s/REPLACEMESTART/${START}/" src/fuzzer.rs
    sed -i "s/REPLACEMESTOP/${STOP}/" src/fuzzer.rs
  else
    echo "Fuzzer doesn't have REPLACEME markers.. skipping"
  fi

}

# Modify config to expedite the fuzzing for this simple example
modify_config() {
  # Initialize the config for the project
  $HOME/.cargo/bin/cargo run -r -- project init-config

  # Change the merge coverage timeout from 60 sec -> 2 sec
  sed -i 's/secs = 60/secs = 2/' /snapchange/snapchange/fuzzer/snapshot/config.toml
}


take_snapshot
copy_snapshot_directory
init_fuzzer
modify_config

FNAME=$(basename $BIN_FILE)
touch /snapchange/snapchange/fuzzer/snapshot/${FNAME}.bin.ghidra.covbps
# cp /snapchange/fuzzer/output/${FNAME}.bin /snapchange/fuzzer/snapshot/
