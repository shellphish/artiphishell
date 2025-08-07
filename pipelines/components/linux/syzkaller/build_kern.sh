#!/bin/bash

set -eux

mkdir -p /kernel/linux
tar -xvf /root/kernel.tar.gz -C /kernel/linux
cd /kernel/linux
./scripts/kconfig/merge_config.sh /kernel/linux/.config /shellphish/syzkaller/kernel.config
make olddefconfig && make -j$(nproc)