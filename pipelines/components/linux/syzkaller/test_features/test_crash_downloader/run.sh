#!/bin/bash

./setup_initial_dirs.sh

ipython --pdb ../../syzkaller_crashes_download.py ./dir_config.yaml ./test_data/crashes