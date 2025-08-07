import argparse
from collections import defaultdict
from pathlib import Path
import re
import shutil
import sys
import time

print("importing watchdog stuff")
import yaml
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import os
import queue
import json


print("Importing from shellphish_crs_utils.pydatatask")
from shellphish_crs_utils.pydatatask import PDTRepo, PDTRepoMonitor

print("Importing from shellphish_crs_utils.filesystem")
from shellphish_crs_utils.filesystem import DirectoryMonitor

    
QUEUES = {
    'descriptions': queue.Queue(),
    'logs': queue.Queue(),
    'reports': queue.Queue(),
}
def reconstitute_syzkaller_crashes(crashes_out_dir, pdt_repo_config):
    repos = {
        'descriptions': (PDTRepo(**pdt_repo_config['crash_descriptions']),PDTRepo(**pdt_repo_config['crash_descriptions_metadatas'])),
        'logs': (PDTRepo(**pdt_repo_config['crash_logs']),PDTRepo(**pdt_repo_config['crash_logs_metadatas'])),
        'reports': (PDTRepo(**pdt_repo_config['crash_reports']),PDTRepo(**pdt_repo_config['crash_reports_metadatas'])),
    }

    crash_descriptions_monitor = PDTRepoMonitor(repos['descriptions'][0], QUEUES['descriptions'])
    crash_description_metadatas_monitor = PDTRepoMonitor(repos['descriptions'][1], QUEUES['descriptions'])
    crash_logs_monitor = PDTRepoMonitor(repos['logs'][0], QUEUES['logs'])
    crash_logs_metadatas_monitor = PDTRepoMonitor(repos['logs'][1], QUEUES['logs'])
    crash_reports_monitor = PDTRepoMonitor(repos['reports'][0], QUEUES['reports'])
    crash_reports_metadatas_monitor = PDTRepoMonitor(repos['reports'][1], QUEUES['reports'])

    # import ipdb; ipdb.set_trace()

    keys_to_check = set()
    with crash_descriptions_monitor, crash_description_metadatas_monitor, \
            crash_logs_monitor, crash_logs_metadatas_monitor, \
            crash_reports_monitor, crash_reports_metadatas_monitor:

        for name, (repo_main, repo_lock) in repos.items():
            keys_to_check.update([(name, key) for key in repo_main.ready_keys()])
            keys_to_check.update([(name, key) for key in repo_lock.ready_keys()])

        while True:
            # Now, monitor the queues to see if new keys are ready for checking
            for queue_name, queue_obj in QUEUES.items():
                try:
                    while updated_key := queue_obj.get_nowait():
                        print(f"Adding {queue_name}:{updated_key} to keys_to_check")
                        sys.stdout.flush()
                        keys_to_check.add((queue_name, updated_key))
                except queue.Empty:
                    pass

            if keys_to_check:
                print(f"Checking {len(keys_to_check)} keys: {list(sorted(keys_to_check))[:20]}...")
                sys.stdout.flush()
                keys_that_still_need_checking = set()
                for key in keys_to_check:
                    repo_type, repo_key = key
                    repo_main, repo_metadata = repos[repo_type]
                    if not repo_main.has_unlocked(repo_key) or not repo_metadata.has_unlocked(repo_key):
                        print(f"Key {repo_type}:{repo_key} is locked, adding it back to the queue")
                        keys_that_still_need_checking.add((repo_type, repo_key))
                        continue
                    print(f"Processing {repo_type}:{repo_key}")
                    sys.stdout.flush()

                    content_paths = repo_main.get_content_paths(repo_key)
                    metadata_paths = repo_metadata.get_content_paths(repo_key)
                    assert not content_paths['cokeyed'] and not metadata_paths['cokeyed']

                    content_path = content_paths['main_repo']
                    metadata_path = metadata_paths['main_repo']
                    with open(metadata_path, 'r') as f:
                        print(f"Opening {metadata_path}")
                        sys.stdout.flush()
                        metadata = yaml.safe_load(f)


                    print(f"Reconstituting {content_path}: {metadata}")
                    sys.stdout.flush()
                    out_path = crashes_out_dir / metadata['path_relative_to_crash_dir']
                    # if repo_type != "descriptions":
                    #     out_path = crashes_out_dir / f'{metadata["syzlang_crash_hash"]}/{repo_type[:-1]}{metadata["syzlang_reproducer_index"]}'
                    # else:
                    #     out_path = crashes_out_dir / f'{metadata["crash_hash"]}/{repo_type[:-1]}'

                    # ensure that the parent directories exist
                    out_path.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy(content_path, out_path)
                    print(f"Reconstituted {content_path} to {out_path}")
                    sys.stdout.flush()

                keys_to_check = keys_that_still_need_checking
                    
            print("Sleeping for 20 seconds")
            sys.stdout.flush()
            time.sleep(20)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Monitor syzkaller crashes from pdt and reconstitute them in a crash directory')
    parser.add_argument('pdt_repo_config', type=str, help='Path to the config file for the PDTRepo')
    parser.add_argument('crash_dir', type=str, help='Directory to dump the syzkaller crashes')
    ARGS = parser.parse_args()

    with open(ARGS.pdt_repo_config, 'r') as f:
        pdt_repo_config = yaml.safe_load(f)

    print(f"Serving the following repo_config: {yaml.safe_dump(pdt_repo_config)}")
    sys.stdout.flush()
    reconstitute_syzkaller_crashes(Path(ARGS.crash_dir), pdt_repo_config)