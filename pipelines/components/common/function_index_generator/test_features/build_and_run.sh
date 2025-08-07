#!/usr/bin/bash

set -e
set -x

pdl --unlock || rm -rf pipeline.lock

pdl

pd inject generate_commit_function_index.target_functions_jsons_dir 1 < ./javacpp_commit.tar.gz
pd inject generate_full_function_index.target_functions_jsons_dir 1 < ./javacpp_full.tar.gz

ipython --pdb -- "$(which pd)" run --verbose --debug-trace
pd status

