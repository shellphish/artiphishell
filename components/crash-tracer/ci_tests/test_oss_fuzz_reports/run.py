#!/usr/bin/env python3

import csv
import hashlib
import os

import tqdm
import yaml

import sys

print(os.getcwd())
CUR_DIR = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CUR_DIR, '..', '..'))
from asan2report import CrashContext

progress = tqdm.tqdm(os.listdir(os.path.join(CUR_DIR, 'test_run_pov_results')))
for f in progress:
    with open(os.path.join(CUR_DIR, 'test_run_pov_results', f), 'rb') as in_file:
        run_pov_metadata = yaml.safe_load(in_file)

    try:
        # print(f'Processing {f}')
        progress.set_description(f'Processing {f}')
        crash = CrashContext(run_pov_metadata)
        crash.collect()

        assert crash.final_sanitizer_type
        assert crash.final_crash_type
        assert crash.crash_action
        assert crash.stack_traces

            # "sanitizer": ctx.final_sanitizer_type,
            # "crash_type": ctx.final_crash_type,
            # "crash_action": ctx.crash_action,
            # "stack_traces": ctx.stack_traces,

    except Exception as e:
        print(run_pov_metadata['run_pov_result']['stderr'].decode('utf-8', 'ignore'))
        print(f'Error processing {f}: {e}')
        raise

   
