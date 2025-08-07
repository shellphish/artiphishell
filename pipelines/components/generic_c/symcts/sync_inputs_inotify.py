import argparse
import hashlib
import os
import shutil
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from queue import Queue, Empty

queue = Queue()
class FuzzerEventHandler(FileSystemEventHandler):
    def on_created(self, event):
        # print(f'on_created: {event.src_path}')
        if 'queue' in event.src_path:
            queue.put(('seed', event.src_path))
        elif 'crashes' in event.src_path:
            queue.put(('crash', event.src_path))
        else:
            print(f'Unknown event: {event.src_path}')

def fetch_from_queue(queue, dest_dir, default=None):
    try:
        return queue.get(block=False)
    except Empty:
        return default

def split_list(lst, pred):
    a = []
    b = []
    for x in lst:
        if pred(x):
            a.append(x)
        else:
            b.append(x)
    return a, b

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Monitor a fuzzer sync dir')
    parser.add_argument('sync_dir', type=str, help='The directory to monitor')
    parser.add_argument('benign_dir', type=str, help='The directory to copy benign inputs to')
    parser.add_argument('crashes_dir', type=str, help='The directory to copy crashes to')
    args = parser.parse_args()

    observer = Observer()
    event_handler = FuzzerEventHandler()
    # import ipdb; ipdb.set_trace()
    for fuzzer_dir in os.listdir(args.sync_dir):
        if not os.path.isdir(os.path.join(args.sync_dir, fuzzer_dir)):
            continue
        
        for subdir in ['queue', 'crashes']:
            os.makedirs(os.path.join(args.sync_dir, fuzzer_dir, subdir), exist_ok=True)
        print(f'Watching {fuzzer_dir}/queue', flush=True)
        observer.schedule(event_handler, os.path.join(args.sync_dir, fuzzer_dir, 'queue'), recursive=False)
        print(f'Watching {fuzzer_dir}/crashes', flush=True)
        observer.schedule(event_handler, os.path.join(args.sync_dir, fuzzer_dir, 'crashes'), recursive=False)

    observer.start()

    pending = set()


    def is_ready(cur):
        if not is_interesting(cur):
            return True
        kind, path = cur
        mtime = os.path.getmtime(path)
        now = time.time()
        return now - mtime > 10 # the file has been stable for 10 seconds
    
    def is_interesting(cur):
        kind, path = cur
        return os.path.basename(path).startswith('id:')

    for fuzzer_dir in os.listdir(args.sync_dir):
        for subdir in ['queue', 'crashes']:
            for file in os.listdir(os.path.join(args.sync_dir, fuzzer_dir, subdir)):
                path = os.path.join(args.sync_dir, fuzzer_dir, subdir, file)
                event = ('seed', path) if subdir == 'queue' else ('crash', path)
                if is_interesting(event) and os.path.isfile(path):
                    pending.add(event)
    while True:
        # print('Checking for pending events...')
        while event := fetch_from_queue(queue, args.benign_dir):
            pending.append(event)

        ready, pending = split_list(pending, is_ready)
        print(f'Found ready events: {ready}')
        print(f'Found pending events: {pending}')
        
        for kind, seed in ready:
            if not is_interesting((kind, seed)):
                continue

            with open(seed, 'rb') as f:
                sha256 = hashlib.sha256(f.read()).hexdigest()
            out_dir = args.crashes_dir if kind == 'crash' else args.benign_dir
            print(f'Copying {seed} to {out_dir}/{sha256}')
            shutil.copy(seed, os.path.join(out_dir, sha256))
        
        # print('Sleeping...')
        time.sleep(20)
        
    
