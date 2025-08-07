#!/bin/bash

set -e
set -x

pushd ./syzlang-bridge
if [ ! -d syzkaller ]; then
   git clone https://github.com/google/syzkaller
fi

pushd syzkaller
git checkout e812177 \
    && mkdir -p workdir/crashes \
    && git apply ../harness_syscall.diff \
    && git apply ../generate_json.diff
echo "syz_harness(blob buffer[in], blob_size len[blob])" > sys/linux/harness.txt
make descriptions
popd

python gen.py
popd
