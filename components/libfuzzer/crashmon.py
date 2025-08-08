#!/usr/bin/env python3

import os
import argparse
from collections import defaultdict
from pathlib import Path
import shutil

import time

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Crash monitor for libFuzzer')
    parser.add_argument('input_dir', type=str, help='Directory to monitor for crashes')
    parser.add_argument('output_dir', type=str, help='Directory to store crashes')
    parser.add_argument('output_metadata_dir', type=str, help='Directory to store metadata')
    parser.add_argument('output_lock_dir', type=str, help='Directory to store lock files')
    parser.add_argument('harness_id', type=str, help='ID of the harness')

    args = parser.parse_args()

    input_dir = Path(args.input_dir)
    output_dir = Path(args.output_dir)
    output_metadata_dir = Path(args.output_metadata_dir)
    output_lock_dir = Path(args.output_lock_dir)
    harness_id = args.harness_id
    crash_id = 0

    while True:
        files = os.listdir(input_dir)
        # Iterate over the crashing files
        for file in files:
            # create the lock file for the crash
            lock_file = output_lock_dir / file
            lock_file.touch()
            # Copy the input file to the output dir
            shutil.copy(input_dir / file, output_dir / file)
            # Create a metadata entry in the outpuf file
            metadata_file = output_metadata_dir / file
            metadata_file.touch()
            metadata_file.write_text(f"harness_id: {harness_id}\ncrash_report_id: {crash_id}")
            # output stuff
            crash_id+=1
            (input_dir / file).unlink()
            lock_file.unlink()
        time.sleep(10)

        
