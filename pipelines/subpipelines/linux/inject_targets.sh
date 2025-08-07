#!/bin/bash

set -e
set -x

pd inject syzdirect.poi_file 1 < ../components/linux/syzdirect/injection_files/5_14_target_poi
pd inject syzdirect.poi_kcov_patch 1 < ../components/linux/syzdirect/injection_files/v5.14.kcov.patch

#pd inject progseed_generate.input_seed_c_harness 1 < ../components/pipeline/targets/Kernel/CVE-2021-43267/poc_src/reduced-poc.c

pd inject tracerguy.syzlang_seed_path 1234 < ../components/linux/tracerguy/seeds/tipc.prog
pd inject tracerguy.syzlang_seed_meta 1234 <<EOF
target_id: "1"
EOF

TARGETS=(
    "1000 c kernel-challenge-001-exemplar-pulled"
    "1001 c kernel-suraj-tipc-reinserted-into-5.14.rc2"
)
for TARGET in "${TARGETS[@]}"; do
    TARGET_ID=$(echo "$TARGET" | awk '{print $1}')
    TARGET_LANG=$(echo "$TARGET" | awk '{print $2}')
    TARGET_NAME=$(echo "$TARGET" | awk '{print $3}')
    TARGET_PATH=../components/pipeline/targets_semis/"$TARGET_LANG"/"$TARGET_NAME"
    pushd "$TARGET_PATH"
    ./package.sh
    popd
    pd inject linterguyRun.target "$TARGET_ID" < "$TARGET_PATH.tar.gz"
done
