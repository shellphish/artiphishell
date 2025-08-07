from pathlib import Path
import sys
import time
from typing import List, Union
from queue import Queue, Empty

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from watchdog.events import EVENT_TYPE_CLOSED, EVENT_TYPE_CREATED, EVENT_TYPE_DELETED, EVENT_TYPE_MODIFIED, EVENT_TYPE_MOVED

class DirectoryMonitor(FileSystemEventHandler):
    def __init__(self, queue: Queue, *monitored_directories: List[Union[str, Path]], recursive=True, observer_cooldown_time_seconds=None):
        self.queue = queue
        self.monitored_directories = [Path(d) for d in monitored_directories]
        self.recursive = recursive
        self.pending_events = Queue()
        self.observer_cooldown_time_seconds = None
        self.observer_cooldown_time_seconds = observer_cooldown_time_seconds if observer_cooldown_time_seconds is not None else 2

        self.observer_for_directory = {}
        
    def __enter__(self):
        for monitored_directory in self.monitored_directories:
            self.observer_for_directory[monitored_directory] = Observer()
            self.observer_for_directory[monitored_directory].schedule(self, monitored_directory, recursive=self.recursive)
            self.observer_for_directory[monitored_directory].start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        # give the observer a bit of time to finish up queuing its stuff
        if self.observer_cooldown_time_seconds:
            time.sleep(self.observer_cooldown_time_seconds)
        for observer in self.observer_for_directory.values():
            observer.stop()

        self.update_pending_events(force_push_pending=True)
        for observer in self.observer_for_directory.values():
            observer.join()
    
    # to be overridden if you like
    def event_is_interesting(self, event):
        return True
    
    def event_is_ready(self, event):
        return True
    
    def compute_output(self, event):
        return event

    def output_computed_event(self, event):
        self.queue.put(self.compute_output(event))

    def external_update(self, force_push_pending=False):
        # this is a hack to allow the queue to forward events that reached maturity even when no new events appear
        # (i.e. the file_unchanged_threshold_seconds has passed without any new events for that file)
        self.update_pending_events(force_push_pending=force_push_pending)

    def on_any_event(self, event):
        if not self.event_is_interesting(event):
            self.update_pending_events()
            return
        
        if self.event_is_ready(event):
            self.output_computed_event(event)
        else:
            self.pending_events.put(event)
        self.update_pending_events()

    def update_pending_events(self, force_push_pending=False):
        to_push_back = []
        try:
            while event := self.pending_events.get(block=False):
                if force_push_pending or self.event_is_ready(event):
                    self.output_computed_event(event)
                else:
                    to_push_back.append(event)
        except Empty:
            pass

        for event in to_push_back:
            self.pending_events.put(event)