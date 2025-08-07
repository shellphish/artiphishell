#!/bin/bash
set -e
set -x

# SHELLPHISH

# This script is gonna be called in this way:
# run.sh run_pov /work/blob harness_nam --> cp_pov --> harness_name
# At that point we take control and just execute this bash script
# 
# The /work/jtrace_config.yaml is put there by the jtrace.py
# inside this script, we can safely call the harness + input
#
# /shellphish/in_docker_jtrace.py MUST be available in the CP container
echo "🏴‍☠️ HARNESS HI-JACKED 🏴‍☠️"
# find out which argument is the pov file, and replace it with /work/pov
POV_MD5=$(echo "known-pov-contents" | md5sum | cut -d' ' -f1)
JAZZER_ARGS=()
for arg in "$@"; do
    if [ -f "$arg" ]; then
        ARG_MD5=$(md5sum "$arg" | cut -d' ' -f1)
        if [ "$ARG_MD5" == "$POV_MD5" ]; then
            JAZZER_ARGS+=("/work/pov")
            continue
        fi
    fi
    JAZZER_ARGS+=("$arg")
done
# run our in-docker monitor
python3 /work/crash-workdir/in_docker_jtrace.py --jazzer-args ${JAZZER_ARGS[@]}
