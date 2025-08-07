#!/bin/bash

# DON'T UNCOMMENT THIS
# set -x

KERNEL_ROOT_DIR=$1

# Directory to output snapshot files
OUTPUT=/snapchange/fuzzer/output
VM_LOG_FILE=/snapchange/fuzzer/vm.log

# Create the output directory
mkdir -p $OUTPUT

# If there are files in the ./IMAGE/output directory from build.sh, copy the .bin files
if [[ -d /data_dir/qemu_stuff/IMAGE/output ]]
then
    for f in $(find bin$ /data_dir/qemu_stuff/IMAGE/output -type f); do
        echo "Found $f.. Copying .bin files into $OUTPUT"
        cp $f $OUTPUT
    done
fi

# Copy over the `vmlinux` into the output directory
cp $KERNEL_ROOT_DIR/vmlinux $OUTPUT

# Start the VM
echo "starting vm"
/data_dir/qemu_stuff/utils/start.sh "$KERNEL_ROOT_DIR" &

sleep 1

# While the VM is booting, wait for the login prompt. Once the login prompt is shown,
# extarct the gdb output and kill the VM
while true; do
    # Login prompt signals that the /etc/rc.local script executed and can extract output
    grep "FUCKYOUIMDONE" "$VM_LOG_FILE" 2>&1 >/dev/null

    # Status code of 0 means the login prompt was found in the vm.log
    if [ $? -eq 0 ]; then
        sleep 10
        echo "[*] Finished booting.. extracting gdb output";
        # /data_dir/qemu_stuff/utils/extract.sh
        python3 /data_dir/qemu_stuff/utils/extract.py $VM_LOG_FILE

        echo "[*] Moving the snapshot data into $OUTPUT"
        mv fuzzvm.* $OUTPUT
        mv gdb.* $OUTPUT

        echo "[*] Found the following files"
        ls -la $OUTPUT

        echo "[*] Found this SNAPSHOT output from the vm log"
        grep SNAPSHOT "$VM_LOG_FILE"

        echo "[*] Killing the VM"
        /data_dir/qemu_stuff/utils/kill.sh

        echo "Done!"
        break
    fi

    echo "[snapshot.sh] Waiting for login prompt.."
    sleep 30
done
