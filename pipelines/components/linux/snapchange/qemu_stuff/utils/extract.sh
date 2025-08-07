#!/bin/sh
set -e
set -x

# Create the directory to mount the image
mkdir -p /mnt/snapchange

# Mount the image from the snapshot
mount -o loop /data_dir/qemu_stuff/IMAGE/bookworm.img /mnt/snapchange

# Copy over the files written by `gdbsnapshot.py`
mv /mnt/snapchange/tmp/gdb.vmmap .
mv /mnt/snapchange/tmp/gdb.modules .
mv /mnt/snapchange/tmp/gdb.symbols .

# Copy over the root symbols and, if found, move the user symbols to .symbols in order to
# combine the symbols into one gdb.symbols
if [ -f /mnt/snapchange/tmp/gdb.symbols.root ]; then
    echo "Combining root and user symbols"
    mv /mnt/snapchange/tmp/gdb.symbols.root .
    mv gdb.symbols gdb.symbols.user 
    python3 /data_dir/qemu_stuff/combine_symbols.py
fi

# Ensure the files are the current user and not root anymore
if [ -f gdb.symbols.root ]; then 
    chown `id -u`:`id -g` gdb.symbols.root
fi
chown `id -u`:`id -g` gdb.symbols
chown `id -u`:`id -g` gdb.modules
chown `id -u`:`id -g` gdb.vmmap

# Unmount the image
umount /mnt/snapchange

# Delete the mount point
rmdir /mnt/snapchange
