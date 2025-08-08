#!/bin/bash

set -e
set -x

rm -rf /snapchange/QEMU
git clone -b v9.0.1 https://github.com/qemu/QEMU /snapchange/QEMU
cd /snapchange/QEMU
patch -p1 < ../qemu_stuff/0001-Snapchange-kvm-patches.patch
mkdir build && cd build && ../configure --target-list=x86_64-softmmu --enable-system --enable-slirp --disable-werror && make -j`nproc`

if [ ! -f "/snapchange/QEMU/build/qemu-system-x86_64" ]; then
    echo "qemu-system-x86_64 not found after qemu build"
    exit 1
fi

wget https://github.com/zolutal/initramfs/releases/download/v1/initramfs.cpio.gz -O /snapchange/qemu_stuff/initramfs.cpio.gz
(
    pushd /snapchange/qemu_stuff/
    unar initramfs.cpio.gz
    mv initramfs.cpio initramfs
    popd
)
