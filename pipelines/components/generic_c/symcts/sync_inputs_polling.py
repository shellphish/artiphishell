import argparse
from collections import defaultdict
import hashlib
import os
import shutil
import subprocess
import tempfile
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from queue import Queue, Empty
from threading import Thread

per_fuzzer_next_crash_id = defaultdict(int)

def parse_name(fname: str):
    assert fname.startswith('id:')
    _id, crash_num, *stuff = fname.split(':')
    stuff = ':'.join(stuff)
    return int(fname[3:].split(':')[0]), stuff

def create_name(num, rest):
    return f'id:{num}:{rest}'

def dump_file(kind, seed):
    with open(seed, 'rb') as f:
        content = f.read()
        sha256 = hashlib.sha256(content).hexdigest()
    out_dir = args.crashes_dir if kind == 'crash' else args.benign_dir
    print(f'Copying {os.path.relpath(seed, args.sync_dir)}')
    tmp = tempfile.mktemp()
    shutil.copy(seed, tmp)
    subprocess.run(['mv', tmp, os.path.join(out_dir, sha256)])
        
class MonitorThread(Thread):
    def __init__(self, out_queue: Queue, sync_dir, benign_dir, crashes_dir, fuzzer_name, subdir):
        super().__init__()
        self.out_queue = out_queue
        self.sync_dir = sync_dir
        self.benign_dir = benign_dir
        self.crashes_dir = crashes_dir
        self.fuzzer_name = fuzzer_name
        self.subdir = subdir
        self.seen = set()

    def is_valid_new_file(self, fname):
        if  fname[:3] != 'id:':
            return False
        if fname in self.seen:
            return False
        if not os.path.isfile(os.path.join(self.sync_dir, self.fuzzer_name, self.subdir, fname)):
            return False
        mtime = os.path.getmtime(os.path.join(self.sync_dir, self.fuzzer_name, self.subdir, fname))
        now = time.time()
        return now - mtime > 10
    
    def run(self) -> None:
        path = os.path.join(self.sync_dir, self.fuzzer_name, self.subdir)

        while True:
            for fname in os.listdir(path):
                if self.is_valid_new_file(fname):
                    self.seen.add(fname)
                    seed_path = os.path.join(path, fname)
                    dump_file('crash' if self.subdir == 'crashes' else 'seed', seed_path)
            time.sleep(60)


def fetch_from_queue(queue, dest_dir, default=None):
    try:
        return queue.get(block=False)
    except Empty:
        return default


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Monitor a fuzzer sync dir')
    parser.add_argument('sync_dir', type=str, help='The directory to monitor')
    parser.add_argument('benign_dir', type=str, help='The directory to copy benign inputs to')
    parser.add_argument('crashes_dir', type=str, help='The directory to copy crashes to')
    args = parser.parse_args()

    # import ipdb; ipdb.set_trace()
    monitor_threads = []
    monitor_queue = Queue()
    for fuzzer_dir in os.listdir(args.sync_dir):
        if not os.path.isdir(os.path.join(args.sync_dir, fuzzer_dir)):
            continue
        
        for subdir in ['queue', 'crashes']:
            os.makedirs(os.path.join(args.sync_dir, fuzzer_dir, subdir), exist_ok=True)
        print(f'Watching {fuzzer_dir}/queue', flush=True)
        monitor_threads.append(MonitorThread(monitor_queue, args.sync_dir, args.benign_dir, args.crashes_dir, fuzzer_dir, 'queue'))
        print(f'Watching {fuzzer_dir}/crashes', flush=True)
        monitor_threads.append(MonitorThread(monitor_queue, args.sync_dir, args.benign_dir, args.crashes_dir, fuzzer_dir, 'crashes'))

    time_to_sleep_per = 60 / len(monitor_threads)
    print(f'Sleeping {time_to_sleep_per} seconds per monitor thread')
    for i, t in enumerate(monitor_threads):
        print(f'Starting monitor thread {i}/{len(monitor_threads)}...')
        t.start()
        time.sleep(time_to_sleep_per)

    pending = set()
    for fuzzer_dir in os.listdir(args.sync_dir):
        for subdir in ['queue', 'crashes']:
            for file in sorted(os.listdir(os.path.join(args.sync_dir, fuzzer_dir, subdir))):
                path = os.path.join(args.sync_dir, fuzzer_dir, subdir, file)
                if os.path.isfile(path):
                    # pending.add(('seed', path) if subdir == 'queue' else ('crash', path))
                    dump_file('crash' if subdir == 'crashes' else 'seed', path)
