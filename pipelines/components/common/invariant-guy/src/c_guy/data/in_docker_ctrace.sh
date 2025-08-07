#!/bin/bash

# SHELLPHISH

# This script is gonna be called in this way:
# run.sh run_pov /work/blob harness_nam --> cp_pov --> harness_name
# At that point we take control and just execute this bash script
# 
# The /work/ctrace_config.yaml is put there by the ctrace.py
# inside this script, we can safely call the harness + input
#
# /shellphish/in_docker_ctrace.py MUST be available in the CP container

echo "🏴‍☠️ HARNESS HIJACKER 🏴‍☠️"
python3 /shellphish/in_docker_ctrace.py --ctrace-config /work/ctrace_config.yaml