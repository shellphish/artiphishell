import argparse
from collections import defaultdict
from pathlib import Path
import re
import sys
import time

import yaml
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import os
import queue
import json

from shellphish_crs_utils.pydatatask import PDTRepo

QUEUES = {
    'descriptions': queue.Queue(),
    'logs': queue.Queue(),
    'reports': queue.Queue(),
}

class SyzcallerCrashesManager:
    def __init__(self, crash_description_repo, crash_log_repo, crash_report_repo):
        self.crash_description_repo = crash_description_repo
        self.crash_log_repo = crash_log_repo
        self.crash_report_repo = crash_report_repo

        self.crash_ids_for_hash = {}
        self.pending_crash_description_uploads = set()
        self.processed_logs = set()
        self.processed_reports = set()
        self.processed_report_ids = set()
        
        self.backlog_descriptions = []
        self.backlog_logs = []
        self.backlog_reports = []

    def schedule_description(self, description_path):
        path = Path(description_path)
        # if the path is at least 10 seconds old, upload it, otherwise return False
        if time.time() - path.stat().st_mtime < 10:
            return False
        if description_path in self.backlog_descriptions:
            return True
        if description_path in self.pending_crash_description_uploads:
            return True
        self.backlog_descriptions.append(Path(description_path))
        return True

    def schedule_log(self, log_path):
        path = Path(log_path)
        # if the path is at least 10 seconds old, upload it, otherwise return False
        if time.time() - path.stat().st_mtime < 10:
            return False
        if log_path in self.backlog_logs:
            return True
        if log_path in self.processed_logs:
            return True
        self.backlog_logs.append(Path(log_path))
        return True

    def schedule_report(self, report_path):
        path = Path(report_path)
        # if the path is at least 10 seconds old, upload it, otherwise return False
        if time.time() - path.stat().st_mtime < 10:
            return False
        if report_path in self.backlog_reports:
            return True # already in the backlog
        if report_path in self.processed_reports:
            return True
        self.backlog_reports.append(Path(report_path))
        return True

    def process_description_upload_results_backlog(self):
        for hash in self.pending_crash_description_uploads:
            if uploaded_id := self.crash_description_repo.get_upload_result(hash):
                self.crash_ids_for_hash[hash] = uploaded_id

        self.pending_crash_description_uploads = [
            hash for hash in self.pending_crash_description_uploads if hash not in self.crash_ids_for_hash
        ]

    def process_description_backlog(self):
        while self.backlog_descriptions:
            description_path = Path(self.backlog_descriptions.pop())
            crash_hash = str(description_path.parent.name)

            self.crash_description_repo.upload(
                crash_hash,
                description_path,
                meta=json.dumps({
                    'crash_hash': crash_hash,
                    'orig_filename': description_path.name,
                    'path_relative_to_crash_dir': os.path.join(crash_hash, description_path.name),
                })
            )
            self.pending_crash_description_uploads.append(crash_hash)

    def process_logs_and_reports_backlog(self):

        todo = [
            ("log", self.backlog_logs, self.crash_log_repo, self.processed_logs),
            ("report", self.backlog_reports, self.crash_report_repo, self.processed_reports),
        ]

        still_pending_logs = defaultdict(list)
        for name, backlog, repo, processed in todo:

            while backlog:
                log_path = Path(backlog.pop())
                assert log_path not in processed

                crash_hash = str(log_path.parent.name)
                if crash_hash not in self.crash_ids_for_hash:
                    still_pending_logs[name].append(log_path)
                    continue

                log_name = log_path.name
                assert log_name.startswith(name)
                log_id = int(log_name[len(name):])
                if name == 'log':
                    # only upload logs for which we have a corresponding report
                    if log_id not in self.processed_report_ids:
                        still_pending_logs[name].append(log_path)
                        continue
                if name == 'report':
                    self.processed_report_ids.add(log_id)
                crash_id = self.crash_ids_for_hash[crash_hash]
                repo.upload(
                    f'{crash_hash}_{log_id}',
                    log_path,
                    meta=yaml.safe_dump({
                        'crash_hash': crash_hash,
                        'orig_filename': log_path.name,
                        'description_pdt_id': crash_id,
                        'reproducer_index': log_id,
                        'path_relative_to_crash_dir': os.path.join(crash_hash, log_path.name),
                    })
                )
                processed.add(log_path)

        cur_time = time.time()
        # only keep the things in the backlog if it hasn't been at least 30 minutes since we've tried to upload it
        self.backlog_logs = [p for p in still_pending_logs["log"] if p.stat().st_mtime + 30 * 60 > cur_time]
        self.backlog_reports = [p for p in still_pending_logs["report"] if p.stat().st_mtime + 30 * 60 > cur_time]

    def process_backlog(self):
        self.process_description_upload_results_backlog()
        self.process_description_backlog()
        self.process_logs_and_reports_backlog()

    def process_queues(self):
    
        to_requeue = defaultdict(list)
        for queue_name, cur_queue in QUEUES.items():
            try:
                while path := cur_queue.get_nowait():
                    schedule_func = {
                        'descriptions': self.schedule_description,
                        'logs': self.schedule_log,
                        'reports': self.schedule_report,
                    }
                    was_scheduled = schedule_func[queue_name](path)
                    print(f"Processing {queue_name} queue: {path} was_scheduled={was_scheduled}")
                    if not was_scheduled:
                        to_requeue[queue_name].append(path)
            except queue.Empty:
                pass

        for queue_name, paths in to_requeue.items():
            for path in paths:
                QUEUES[queue_name].put(path)

    def update(self):
        self.process_queues()
        self.process_backlog()

class SyzcallerCrashesMonitor(FileSystemEventHandler):
    def on_any_event(self, event):
        if event.event_type != 'created' or event.is_directory:
            return
        
        print(f"[CREATED]{event.src_path} has been {event.event_type}: {event!r}\n")
        filename = os.path.basename(event.src_path)
        if re.fullmatch(r'log\d+', filename):
            QUEUES['logs'].put(Path(event.src_path))
        elif re.fullmatch(r'report\d+', filename):
            QUEUES['reports'].put(Path(event.src_path))
        elif re.fullmatch(r'description', filename):
            QUEUES['descriptions'].put(Path(event.src_path))

if __name__ == "__main__":
    print("Starting the syzkaller crash monitor")
    parser = argparse.ArgumentParser(description='Monitor syzkaller crashes')
    parser.add_argument('crash_dir', type=str, help='Directory to monitor for syzkaller crashes')
    parser.add_argument('pdt_repo_config', type=str, help='Path to the config file for the PDTRepo')
    ARGS = parser.parse_args()

    with open(ARGS.pdt_repo_config, 'r') as f:
        pdt_repo_config = yaml.safe_load(f)
        
    print(f"Serving the following repo_config: {yaml.safe_dump(pdt_repo_config)}")
    sys.stdout.flush()
    crash_descriptions = PDTRepo(**pdt_repo_config['crash_descriptions'])
    crash_logs = PDTRepo(**pdt_repo_config['crash_logs'])
    crash_reports = PDTRepo(**pdt_repo_config['crash_reports'])

    crash_manager = SyzcallerCrashesManager(crash_descriptions, crash_logs, crash_reports)

    event_handler = SyzcallerCrashesMonitor()
    observer = Observer()
    observer.schedule(event_handler, ARGS.crash_dir, recursive=True)
    observer.start()
    while True:
        try:
            crash_manager.update()
            time.sleep(1)
        except KeyboardInterrupt:
            observer.stop()
            break
    observer.join()