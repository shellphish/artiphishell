#!/bin/bash

set -x
set -e

# Variables affected by options
ARCH=$(uname -m)
RELEASE=/data_dir/qemu_stuff/IMAGE/bookworm.img
FEATURE=minimal
SEEK=2047
PERF=false
OUT=/snapchange/fuzzer/output
USER=root

ARG_COUNT=$#
BIN_NAME="$1"

echo "build.sh-ing"

#
if [ $USER = 'root' ]; then
    HOMEDIR=/root
else
    HOMEDIR=/home/$USER

fi

do_stuff () {
    DIR=$1
    # Make the directory to hold the original binary to copy into the snapshot directory
    mkdir -p $DIR$HOMEDIR

    # If given any new arguments, rewrite the rc.local boot script
    if [ $ARG_COUNT -gt 0 ];
    then
        # Remove previous snapshot script
        rm $DIR/etc/rc.local || true

        # Copy the binary into the root directory of the image
        cp $BIN_NAME $DIR$HOMEDIR/`basename $BIN_NAME`

        # Make the directory to hold the original binary to copy into the snapshot directory
        mkdir -p $OUT

        # Copy the binary into the output directory
        cp $BIN_NAME $OUT/`basename $BIN_NAME`.bin

        # Make the copied binary executable
        chmod +x $DIR$HOMEDIR/`basename $BIN_NAME`

        touch $DIR/etc/rc.local || true

        # Init the rc.local script
        echo "#!/bin/sh -ex"  | tee -a $DIR/etc/rc.local

        echo "TESTASDF"
        cat $DIR/etc/rc.local

        echo "export CHESS=1" | tee -a $DIR/etc/rc.local
        # Enable the snapshot
        echo "export SNAPSHOT=1" | tee -a $DIR/etc/rc.local

        # If user is not root, run gdb under gdb in order to gain kernel symbols as root
        if [ $USER != 'root' ]; then
            echo "gdb --command=$HOMEDIR/gdbcmds --args gdb" | tee -a $DIR/etc/rc.local

            # Copy the symbols found under root
            echo "mv /tmp/gdb.symbols /tmp/gdb.symbols.root" | tee -a $DIR/etc/rc.local

            # Remove the modules and memory map for this execution since we only care about
            # symbols
            echo "rm /tmp/gdb.modules" | tee -a $DIR/etc/rc.local
            echo "rm /tmp/gdb.vmmap" | tee -a $DIR/etc/rc.local
        fi

        # If user is not root, run gdb under the given user
        if [ $USER != 'root' ]; then
            echo "su $USER -c '" | tee -a $DIR/etc/rc.local
        fi

        echo "printf 'A%.0s' {1..2000} > /tmp/inp" | tee -a $DIR/etc/rc.local

        # Create the script to start on boot
        echo "gdb --command=$HOMEDIR/gdbcmds --args $HOMEDIR/`basename $BIN_NAME` /tmp/inp"  | tee -a $DIR/etc/rc.local
        shift 1

        # If user is not root, close the command executed
        if [ $USER != 'root' ]; then
            echo "'" | tee -a $DIR/etc/rc.local
        fi

        # Add a newline
        echo "" | tee -a $DIR/etc/rc.local

        # Copy the GDB output files back to the local directory
        echo "cp /tmp/gdb* $HOMEDIR"  | tee -a $DIR/etc/rc.local

        # Ensure the output files are actually written to the image
        # echo "sync" | tee -a $DIR/etc/rc.local

        # Status check after GDB exits to see if the files are written
        echo "ls -la $HOMEDIR"  | tee -a $DIR/etc/rc.local

        echo "echo \"===== GDB SYMBOLS START =====\"" | tee -a $DIR/etc/rc.local
        echo "cat /tmp/gdb.symbols" | tee -a $DIR/etc/rc.local
        echo "echo \"====== GDB SYMBOLS END ======\"" | tee -a $DIR/etc/rc.local

        echo "echo \"===== GDB MODULES START =====\"" | tee -a $DIR/etc/rc.local
        echo "cat /tmp/gdb.modules" | tee -a $DIR/etc/rc.local
        echo "echo \"====== GDB MODULES END ======\"" | tee -a $DIR/etc/rc.local

        echo "echo \"======= GDB VMMAP START =======\"" | tee -a $DIR/etc/rc.local
        echo "cat /tmp/gdb.vmmap" | tee -a $DIR/etc/rc.local
        echo "echo \"======== GDB VMMAP END ========\"" | tee -a $DIR/etc/rc.local

        # Make the script executable and owned by root
        chmod +x $DIR/etc/rc.local
        chown root:root $DIR/etc/rc.local

    fi

    # Add a line to let us know that the script is done
    echo "echo 'FUCKYOUIMDONE'" | tee -a $DIR/etc/rc.local
    # Add newline to thes script
    echo "" | tee -a $DIR/etc/rc.local

    # Copy in the gdbsnapshot.py
    cp /data_dir/qemu_stuff/gdbsnapshot.py $DIR$HOMEDIR/gdbsnapshot.py

    # tail $DIR$HOMEDIR/gdbsnapshot.py

    # Try to remove the old gdbcmds since we are writing a new one below
    rm $DIR$HOMEDIR/gdbcmds || true

    if [[ "$LIBFUZZER" ]]; then
        echo "LIBFUZZER SNAPSHOT DETECTED"
        echo "Taking a snapshot at LLVMFuzzerTestOneInput"

        # Ignore leak detection.
        echo 'set environment ASAN_OPTIONS=detect_leaks=0' | tee -a $DIR$HOMEDIR/gdbcmds

        # Stop at the first chance in the target in order to enable the breakpoint on LLVMFuzzerTestOneInput
        echo 'start'                         | tee -a $DIR$HOMEDIR/gdbcmds
        echo 'del *'                         | tee -a $DIR$HOMEDIR/gdbcmds
        echo 'x/16xb LLVMFuzzerTestOneInput' | tee -a $DIR$HOMEDIR/gdbcmds

        # Remove all coverage trace from libfuzzer since we are using breakpoint coverage in Snapchange
        echo 'set {unsigned char}(__sanitizer_cov_trace_const_cmp4+0)=0xc3'  | tee -a $DIR$HOMEDIR/gdbcmds
        echo 'set {unsigned char}(__sanitizer_cov_trace_cmp)=0xc3'           | tee -a $DIR$HOMEDIR/gdbcmds
        echo 'set {unsigned char}(__sanitizer_cov_trace_cmp1)=0xc3'          | tee -a $DIR$HOMEDIR/gdbcmds
        echo 'set {unsigned char}(__sanitizer_cov_trace_cmp2)=0xc3'          | tee -a $DIR$HOMEDIR/gdbcmds
        echo 'set {unsigned char}(__sanitizer_cov_trace_cmp4)=0xc3'          | tee -a $DIR$HOMEDIR/gdbcmds
        echo 'set {unsigned char}(__sanitizer_cov_trace_cmp8)=0xc3'          | tee -a $DIR$HOMEDIR/gdbcmds
        echo 'set {unsigned char}(__sanitizer_cov_trace_const_cmp1)=0xc3'    | tee -a $DIR$HOMEDIR/gdbcmds
        echo 'set {unsigned char}(__sanitizer_cov_trace_const_cmp2)=0xc3'    | tee -a $DIR$HOMEDIR/gdbcmds
        echo 'set {unsigned char}(__sanitizer_cov_trace_const_cmp4)=0xc3'    | tee -a $DIR$HOMEDIR/gdbcmds
        echo 'set {unsigned char}(__sanitizer_cov_trace_const_cmp8)=0xc3'    | tee -a $DIR$HOMEDIR/gdbcmds
        echo 'set {unsigned char}(__sanitizer_cov_trace_div4)=0xc3'          | tee -a $DIR$HOMEDIR/gdbcmds
        echo 'set {unsigned char}(__sanitizer_cov_trace_div8)=0xc3'          | tee -a $DIR$HOMEDIR/gdbcmds
        echo 'set {unsigned char}(__sanitizer_cov_trace_gep)=0xc3'           | tee -a $DIR$HOMEDIR/gdbcmds
        echo 'set {unsigned char}(__sanitizer_cov_trace_pc)=0xc3'            | tee -a $DIR$HOMEDIR/gdbcmds
        echo 'set {unsigned char}(__sanitizer_cov_trace_pc_guard)=0xc3'      | tee -a $DIR$HOMEDIR/gdbcmds
        echo 'set {unsigned char}(__sanitizer_cov_trace_pc_guard_init)=0xc3' | tee -a $DIR$HOMEDIR/gdbcmds
        echo 'set {unsigned char}(__sanitizer_cov_trace_pc_indir)=0xc3'      | tee -a $DIR$HOMEDIR/gdbcmds
        echo 'set {unsigned char}(__sanitizer_cov_trace_switch)=0xc3'        | tee -a $DIR$HOMEDIR/gdbcmds

        # Insert (int3 ; vmcall) on the LLVMFuzzerTestOneInput
        echo 'set {unsigned char}(LLVMFuzzerTestOneInput+0x0)=0xcc' | tee -a $DIR$HOMEDIR/gdbcmds
        echo 'set {unsigned char}(LLVMFuzzerTestOneInput+0x1)=0x0f' | tee -a $DIR$HOMEDIR/gdbcmds
        echo 'set {unsigned char}(LLVMFuzzerTestOneInput+0x2)=0x01' | tee -a $DIR$HOMEDIR/gdbcmds
        echo 'set {unsigned char}(LLVMFuzzerTestOneInput+0x3)=0xc1' | tee -a $DIR$HOMEDIR/gdbcmds
        echo 'set {unsigned char}(LLVMFuzzerTestOneInput+0x4)=0xcd' | tee -a $DIR$HOMEDIR/gdbcmds
        echo 'set {unsigned char}(LLVMFuzzerTestOneInput+0x5)=0xcd' | tee -a $DIR$HOMEDIR/gdbcmds
        echo 'set {unsigned char}(LLVMFuzzerTestOneInput+0x6)=0xcd' | tee -a $DIR$HOMEDIR/gdbcmds
        echo 'set {unsigned char}(LLVMFuzzerTestOneInput+0x7)=0xcd' | tee -a $DIR$HOMEDIR/gdbcmds
        echo 'set {unsigned char}(LLVMFuzzerTestOneInput+0x8)=0xcd' | tee -a $DIR$HOMEDIR/gdbcmds
        echo 'set {unsigned char}(LLVMFuzzerTestOneInput+0x9)=0xcd' | tee -a $DIR$HOMEDIR/gdbcmds
        echo 'set {unsigned char}(LLVMFuzzerTestOneInput+0xa)=0xcd' | tee -a $DIR$HOMEDIR/gdbcmds
        echo 'set {unsigned char}(LLVMFuzzerTestOneInput+0xb)=0xcd' | tee -a $DIR$HOMEDIR/gdbcmds
        echo 'set {unsigned char}(LLVMFuzzerTestOneInput+0xc)=0xcd' | tee -a $DIR$HOMEDIR/gdbcmds
        echo 'set {unsigned char}(LLVMFuzzerTestOneInput+0xd)=0xcd' | tee -a $DIR$HOMEDIR/gdbcmds
        echo 'set {unsigned char}(LLVMFuzzerTestOneInput+0xe)=0xcd' | tee -a $DIR$HOMEDIR/gdbcmds
        echo 'set {unsigned char}(LLVMFuzzerTestOneInput+0xf)=0xcd' | tee -a $DIR$HOMEDIR/gdbcmds

        # Continue execution until the LLVMFuzzerTestOneInput and take the snapshot as normal
        echo 'continue'                                         | tee -a $DIR$HOMEDIR/gdbcmds
        echo "source $HOMEDIR/gdbsnapshot.py"                   | tee -a $DIR$HOMEDIR/gdbcmds
        echo 'ni'                                               | tee -a $DIR$HOMEDIR/gdbcmds
        echo 'ni'                                               | tee -a $DIR$HOMEDIR/gdbcmds
        echo 'quit'                                             | tee -a $DIR$HOMEDIR/gdbcmds
    else
        # Default snapshot implementation that expects (int3 ; vmcall) to be in the target
        #
        # Execute to the first int3, execute the gdbsnapshot, execute vmcall, then exit
        echo 'set pagination off'             | tee -a $DIR$HOMEDIR/gdbcmds
        echo 'run'                            | tee -a $DIR$HOMEDIR/gdbcmds
        echo "source $HOMEDIR/gdbsnapshot.py" | tee -a $DIR$HOMEDIR/gdbcmds
        echo 'ni'                             | tee -a $DIR$HOMEDIR/gdbcmds
        echo 'ni'                             | tee -a $DIR$HOMEDIR/gdbcmds
        echo 'quit'                           | tee -a $DIR$HOMEDIR/gdbcmds
    fi


}

# # Sanity check the script was written properly
# echo "!!! Sanity check the startup script !!!"
# cat $DIR/etc/rc.local
# echo "!!! Sanity check the startup script !!!"
#
# # Display the home directory as a sanity check
# echo "!!! Sanity check the home directory !!!"
# sudo ls -la $DIR$HOMEDIR
# echo "!!! Sanity check the home directory !!!"

# Build a disk image
# dd if=/dev/zero of=$RELEASE bs=1M seek=$SEEK count=1
# sudo mkfs.ext4 -F $RELEASE

#BASE_DIR=chroot
#mkdir -p /mnt/$BASE_DIR
#mount -o loop $RELEASE /mnt/$BASE_DIR
#do_stuff /mnt/$BASE_DIR
## sudo cp -a $DIR/. /mnt/$BASE_DIR/.
#umount /mnt/$BASE_DIR


do_stuff /data_dir/qemu_stuff/initramfs

pushd /data_dir/qemu_stuff/initramfs
./gen_cpio.sh 2>/dev/null 1>&2
popd
