#!/bin/bash

set -e
set -x

SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
echo "SCRIPTPATH: $SCRIPTPATH"

TARGET="snapchange"
if [ "$#" -eq 1 ]; then
    TARGET="$1"
fi

case "$TARGET" in
    snapchange|lark)
        ;;
    *)
        echo "Invalid Target: $TARGET! must be one of: [\"snapchange\", \"lark\"]"
        exit 1
        ;;
esac

if [ ! -d syzkaller ]; then
   git clone https://github.com/google/syzkaller
fi

pushd syzkaller
(
    git checkout e812177 \
        && mkdir -p workdir/crashes \
        && git apply "$SCRIPTPATH/../syzlang-bridge/patches/harness_syscall.diff" \
        && git apply "$SCRIPTPATH/../syzlang-bridge/patches/generate_json.diff"
    echo "syz_harness(blob buffer[in], blob_size len[blob])" > sys/linux/harness.txt
    make descriptions
)
popd

python3 gen_grammar.py "$TARGET"
