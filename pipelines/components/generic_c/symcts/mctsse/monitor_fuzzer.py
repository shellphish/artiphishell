
import os
import time
import logging
import argparse
from os.path import join
import shutil

parser = argparse.ArgumentParser()
parser.add_argument('sync_directory')
parser.add_argument('monitor_directory')
parser.add_argument('--interval', type=float, help='The interval to sample the current inputs in. (in seconds, float allowed)', default=1.0)
ARGS = parser.parse_args()


l = logging.getLogger('input_sampler')
logging.basicConfig(level='DEBUG')

os.makedirs(ARGS.monitor_directory, exist_ok=True)
START = time.time()
CUR = START
while True:
    CUR += ARGS.interval
    to_sleep = max(CUR - time.time(), 0)
    time.sleep(to_sleep)
    l.debug(f'Waiting for next interval: {to_sleep} seconds')
    for fuzzer_name in os.listdir(ARGS.sync_directory):
        inp_name = join(ARGS.sync_directory, fuzzer_name, '.cur_input')
        outp_name = join(ARGS.monitor_directory, f'{fuzzer_name}_{CUR}.input')
        try:
            shutil.copy(inp_name, outp_name)
        except Exception as ex:
            l.error(f"Error when copying sampled file: {ex}")
