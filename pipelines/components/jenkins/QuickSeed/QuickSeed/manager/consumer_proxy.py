import time, threading
from abc import ABC, abstractmethod
from collections import defaultdict
import logging
from queue import Empty
_l = logging.getLogger(__name__)
_l.setLevel(logging.INFO)
class Proxy:
    def __init__(self, queue):
        self.queue = queue
        self.workers = {} 
        self.thread = threading.Thread(target=self.operate)
        self.task_counter = defaultdict(int)
   
    def add_worker(self, worker):
        self.workers[worker.task_type] = worker

    def start(self):
        self.thread.start()
    
    def wait_finish(self):
        self.thread.join()

    @abstractmethod
    def operate(self):
        pass

class ConsumerProxy(Proxy):
    def operate(self):
        while True:
            if len(self.workers) == 0:
                continue
            try:
                task = self.queue.get(timeout=60)
            except Empty:
                break

            if task is None:
                # _l.info("task is none")
                break
            else:
                self.task_counter[type(task).__name__] += 1
                if self.task_counter['HarnessTask'] > 20 or  self.task_counter['FilterPoisTask'] > 20:
                    _l.critical("max run for QuickSeed. Exits")
                    break
                _l.info(f"task in {task} task name is {type(task).__name__}")
                _l.info(f"queue id is {id(self.queue)}")
                self.workers[type(task).__name__].operate(task)
                _l.debug(f"consuming task {task}")
            # take a nap for now, because we are not doing anything yet
            time.sleep(1)
