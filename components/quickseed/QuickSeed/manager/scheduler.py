import logging
import sys
import threading
import traceback
from abc import abstractmethod
from collections import defaultdict, deque
from queue import Empty, Queue, PriorityQueue
from typing import Any, Callable
from QuickSeed.llm import BlockerAnalyzerTask

_l = logging.getLogger(__name__)


class Scheduler:
    TERMINATION_SIGNAL = "TERMINATION_SIGNAL"
    def __init__(self, min_workers: int = 2, max_workers: int = 4, max_queue_size: int = 1000):
        """
        Initialize the custom thread pool.
        
        Args:
            min_workers: Minimum number of worker threads
            max_workers: Maximum number of worker threads
        """
        # Replace Queue with deque + condition variable for priority support
        self.task_deque = deque()
        self.task_condition = threading.Condition()
        
        self.result_queue = Queue()
        self.min_workers = min_workers
        self.max_workers = max_workers
        self.active_workers = 0
        self.shutdown_flag = threading.Event()
        self.workers = []
        self.lock = threading.Lock()
        self.pending_tasks = 0
        self.tasks_complete = threading.Event()
        self.tasks_complete.set()

        # Add worker status tracking for debugging
        self.worker_status = {}  # worker_id -> status
        self.worker_counter = 0
        self.max_queue_size = max_queue_size
        import signal
        signal.signal(signal.SIGINT, self._signal_handler)

    def start(self):
        """Start the thread pool with minimum number of workers."""
        for _ in range(self.min_workers):
            self._add_worker()

    def _add_worker(self):
        """Add a new worker thread to the pool."""
        with self.lock:
            if self.active_workers < self.max_workers:
                self.worker_counter += 1
                worker_id = self.worker_counter
                worker = threading.Thread(target=self._worker_loop, args=(worker_id,))
                worker.daemon = True
                worker.start()
                self.workers.append(worker)
                self.active_workers += 1
                self.worker_status[worker_id] = "starting"
                _l.info(f"Added new worker {worker_id}. Active workers: {self.active_workers}")

    def _remove_worker(self):
        """Remove a worker thread from the pool."""
        with self.lock:
            self.active_workers -= 1
            _l.info(f"Removed worker. Active workers: {self.active_workers}. Pending tasks: {self.pending_tasks}. Shutdown flag is {self.shutdown_flag}, tasks_complete is {self.tasks_complete}")

    def _get_task_with_timeout(self, timeout=1):
        """Get a task from the deque with timeout."""
        with self.task_condition:
            if not self.task_deque and not self.shutdown_flag.is_set():
                # Wait for a task or timeout
                self.task_condition.wait(timeout=timeout)
            
            if self.task_deque:
                return self.task_deque.popleft()
            else:
                raise Empty()

    def _worker_loop(self, worker_id):
        """Main worker loop for processing tasks."""
        _l.info(f"Worker {worker_id} started")
        self.worker_status[worker_id] = "waiting"
        
        while not self.shutdown_flag.is_set():
            try:
                self.worker_status[worker_id] = "getting_task"
                # Try to get a task with timeout
                task, args, kwargs = self._get_task_with_timeout(timeout=1)
                
                self.worker_status[worker_id] = f"executing_task_{task.__name__ if hasattr(task, '__name__') else 'unknown'}"
                _l.debug(f"Worker {worker_id} executing task: {task}")

                # Execute the task
                try:
                    result = task(*args, **kwargs)
                    if args and isinstance(args[0], BlockerAnalyzerTask):
                        # BlockerAnalyzerTask should has the highest priority
                        self.result_queue.put((0, True, result))
                    else:
                        self.result_queue.put((1, True, result))
                    _l.debug(f"Worker {worker_id} completed task successfully")
                except Exception as e:
                    tb = traceback.format_exc()
                    self.result_queue.put((2, False, e))
                    _l.error(f"Worker {worker_id} task execution error {e}: {tb}")

                with self.lock:
                    self.pending_tasks -= 1
                    if self.pending_tasks == 0:
                        self.tasks_complete.set()
                
                self.worker_status[worker_id] = "waiting"

            except KeyboardInterrupt:
                _l.info(f"Worker {worker_id} interrupted")
                self.shutdown(wait=False)
                break
            except (Empty, TimeoutError):
                _l.info(f"Worker {worker_id} - No task available. Waiting for new tasks")
                self.worker_status[worker_id] = "timing_out"
                # No task available, consider removing this worker
                self._remove_worker()
                break

        self.worker_status[worker_id] = "exited"
        _l.info(f"Worker {worker_id} exited")

    def submit_task(self, task: Callable, *args, **kwargs) -> None:
        """Submit a task to the thread pool (added to end of queue)."""
        with self.lock:
            if self.pending_tasks == 0:
                self.tasks_complete.clear()
            self.pending_tasks += 1

        # Add task to end of deque (normal priority)
        with self.task_condition:
            self.task_deque.append((task, args, kwargs))
            self.task_condition.notify()  # Wake up a waiting worker

        # Check if we need more workers (including case where no workers exist)
        should_add_worker = False
        with self.lock:
            if self.active_workers == 0 and len(self.task_deque) > 0:
                # No workers exist, create at least one
                should_add_worker = True
            elif (len(self.task_deque) > 0 and  # Tasks waiting
                  self.active_workers < self.max_workers):  # Room for more workers
                # Add worker if there are waiting tasks and we can add more workers
                should_add_worker = True
        
        # Call _add_worker() outside the lock to avoid deadlock
        if should_add_worker:
            self._add_worker()

    def submit_task_prioritize(self, task: Callable, *args, **kwargs) -> None:
        """Submit a high-priority task to the front of the queue."""
        with self.lock:
            if self.pending_tasks == 0:
                self.tasks_complete.clear()
            self.pending_tasks += 1

        # Add task to front of deque (high priority)
        with self.task_condition:
            self.task_deque.appendleft((task, args, kwargs))
            self.task_condition.notify()  # Wake up a waiting worker

        # Check if we need more workers (including case where no workers exist)
        should_add_worker = False
        with self.lock:
            if self.active_workers == 0 and len(self.task_deque) > 0:
                # No workers exist, create at least one
                should_add_worker = True
            elif (len(self.task_deque) > 0 and  # Tasks waiting
                  self.active_workers < self.max_workers): 
                should_add_worker = True
        
        # Call _add_worker() outside the lock to avoid deadlock
        if should_add_worker:
            self._add_worker()

    def get_result(self, timeout: float = None) -> Any:
        """Get the next available result from the result queue."""
        return self.result_queue.get(timeout=timeout)

    def shutdown(self, wait: bool = True):
        """Shutdown the thread pool."""
        self.shutdown_flag.set()
        
        # Wake up all waiting workers
        with self.task_condition:
            self.task_condition.notify_all()
            
        if wait:
            _l.info(f"There are {len(self.workers)} workers. Waiting for {self.pending_tasks} tasks to complete")
            for worker in self.workers:
                worker.join()
        _l.info("Thread pool shutdown complete")

    def debug_worker_status(self):
        """Debug method to show what each worker is doing."""
        with self.lock:
            _l.info(f"=== WORKER STATUS DEBUG ===")
            _l.info(f"Active workers: {self.active_workers}")
            _l.info(f"Pending tasks: {self.pending_tasks}")
            _l.info(f"Queue size: {len(self.task_deque)}")
            _l.info(f"Worker statuses:")
            for worker_id, status in self.worker_status.items():
                _l.info(f"  Worker {worker_id}: {status}")
            _l.info("===========================")

    def wait_finish(self, timeout=None):
        """Wait for all submitted tasks to complete."""
        try:
            if timeout == 0:
                return self.tasks_complete.is_set()
            else:
                result = self.tasks_complete.wait(timeout=timeout)
                return result
        except KeyboardInterrupt:
            _l.info("Keyboard interrupt received during wait_finish")
            self.shutdown(wait=False)  # Initiate shutdown
            return False  # Indicate that we didn't complete normally

    def _signal_handler(self, signum, frame):
        """Signal handler for SIGINT."""
        _l.info("Received SIGINT. Shutting down thread pool")
        self.shutdown(wait=False)
        sys.exit(0)

    def submit_termination_task(self) -> None:
        """Submit a special termination task that puts a termination signal in the result queue."""
        _l.info("Submitting termination task to signal post-processor shutdown")
        def termination_task():
            """Special task that returns a termination signal."""
            return self.TERMINATION_SIGNAL
        
        # Submit the termination task with high priority so it gets processed quickly
        self.submit_task(termination_task)

        
    def get_queue_available_space(self) -> int:
        """Get how many more tasks can be added to the queue."""
        with self.task_condition:
            return max(0, self.max_queue_size - len(self.task_deque))