import fcntl
import logging
import os
import random
import shutil
import string
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from threading import Event

from coveragelib.parsers.calltrace_coverage import Java_Calltrace_Yajta
from shellphish_crs_utils.models.oss_fuzz import LanguageEnum
import yaml
from shellphish_crs_utils.models.crs_reports import RunImageInBackgroundResult
from shellphish_crs_utils.oss_fuzz.instrumentation.coverage_fast import \
    CoverageFastInstrumentation
from shellphish_crs_utils.oss_fuzz.project import InstrumentedOssFuzzProject
from shellphish_crs_utils.utils import artiphishell_should_fail_on_error
from watchdog.events import FileSystemEventHandler
from watchdog.observers.polling import PollingObserver

from coveragelib import Parser, log
from .errors import BuddyTracerDiedException

l = logging.getLogger("coveragelib")
l.setLevel(logging.INFO)

class CovlibResultMonitorHandler(FileSystemEventHandler):
    '''
    This class is a watchdog event handler that is used to monitor the results folder.
    '''
    def __init__(self, tracer, covlib_done_files_at, covlib_results_at, default_raw_coverage_file, seed_names, stop_event):
        self.tracer = tracer
        self.covlib_results_at = covlib_results_at
        self.covlib_done_files_at = covlib_done_files_at
        self.default_raw_coverage_file = default_raw_coverage_file
        self.seed_names = seed_names

        # We are waiting for these files to appear in the result folder.
        self.raw_coverage_files = set([
            self.default_raw_coverage_file.format(seed_name=seed_name) for seed_name in seed_names
        ])

        self.num_of_expected_results = len(self.raw_coverage_files)
        self.worklist = self.raw_coverage_files.copy()
        self.stop_event = stop_event

        self.monitor_started_at = time.time()

        # Start periodic execution in a separate thread.
        # This is a heart-beat to make sure that the tracer is always up. Otherwise we would
        # wait indefinitely...
        self.scheduler_thread = threading.Thread(target=self.run_periodically, daemon=True)
        self.scheduler_thread.start()

    def run_periodically(self):
        '''
        This function makes sure the tracer docker container stays up.
        '''
        while not self.stop_event.is_set():
            try:
                self.tracer._Yajta__ensure_tracer_is_alive()
            except AssertionError:
                l.critical("[CRITICAL] The buddy tracer container is not running. Aborting.")
                self.stop_event.set()
            time.sleep(2)  # Wait 2 seconds before running again

    def on_moved(self, event):
        # forking polling observer creating "moved" events instead of created is forking us
        self.do_stuff(event.dest_path)

    def on_created(self, event):
        self.do_stuff(event.src_path)

    def do_stuff(self, src_path):

        if len(self.worklist) == 0:
            self.stop_event.set()

        if src_path in self.worklist:
            self.worklist.remove(src_path)

            # We are monitoring files in the self.covlib_done_files_at.
            # Whenever one of those files appear, we know we have the corresponding coverage result
            # in the self.covlib_results_at folder.
            cov_file_path = os.path.join(self.covlib_results_at, os.path.basename(src_path))
            print(f"Expecting coverage file {cov_file_path}")

            # If the size of the file at the cov_file_path is 0, we are gonna ignore it
            # and raise a warning
            if os.path.getsize(cov_file_path) == 0:
                l.warning("[WARNING] The coverage file %s is empty", cov_file_path)

            shutil.move(cov_file_path, self.tracer.out_dir / os.path.basename(cov_file_path))
            os.remove(src_path)

        if len(self.worklist) == 0:
            self.stop_event.set()



MYROCO_CONFIG_TEMPLATE = '''"instrument_only": "":
"insclasspattern": "<CLASSES_IN_SCOPE>"
"input_watchdir": "/corpus/<HARNESS_NAME>"
"exec_folder": "/out/dumps/"
"dump_dir": "<DUMP_CLASSES_FOLDER>"
'''

class Yajta:
    def __init__(
        self,
        target_dir : Path,
        harness_name : str,
        out_dir=None,
        parser=None,
        aggregate=False,
        extra_excludes:str=None,
        debug_mode=False,
        crash_mode=False,
    ):
        
        # NOTE: If by mistake someone passes the aggregate=True, we are gonna ignore it.
        # This is because I want people to just use Yajta as they are using a normal Tracer.
        if aggregate == True:
            print("[WARNING] The aggregate option is not supported by the Yajta. Setting it to False.")
        self.aggregate = False

        self.debug_mode = debug_mode
        # Note this is not to be used unless its really needed as it slows things down
        # This is a hidden feature for very specific needed
        self.crash_mode = crash_mode
        target_dir = Path(target_dir).resolve()

        # The target dir MUST be in /shared/
        assert str(target_dir).startswith("/shared/")

        # To make sure the user is giving us an oss-fuzz-dir
        # we are gonna assert that the folder "artifacts"
        artifacts_path = os.path.join(target_dir, "artifacts")
        assert os.path.isdir(artifacts_path)
        harness_path = os.path.join(artifacts_path, "out", harness_name)
        assert os.path.isfile(harness_path), f"The harness {harness_name} does not exist in the target directory {target_dir}"

        # If this is the first time we are tracing this project and harness, we want to
        # create the folder for the corpus
        # Generate a temporary name for the corpus
        self.covlib_workdir = f'{target_dir}/artifacts/work/coveragelib-' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
        self.covlib_queue_folder_at = f'{self.covlib_workdir}/seeds-queue'
        self.coverage_harnesses_corpuses_at = self.covlib_workdir  + '/corpus/'
        self.coverage_harness_corpus_at = f"{self.coverage_harnesses_corpuses_at}/{harness_name}"
        self.covlib_results_at = self.covlib_workdir + '/raw-results/'
        self.covlib_done_files_at = self.covlib_workdir + '/raw-results-done-files/'

        os.makedirs(self.coverage_harness_corpus_at, exist_ok=True)
        os.makedirs(self.covlib_results_at, exist_ok=True)
        os.makedirs(self.covlib_done_files_at, exist_ok=True)
        os.makedirs(self.covlib_queue_folder_at, exist_ok=True)

        assert str(self.coverage_harnesses_corpuses_at).startswith("/shared/")

        # This is the directory of the oss-fuzz-cp
        self.target_dir = target_dir

        # We are gonna move the result of the coverage tracer in this directory
        if out_dir:
            out_dir = Path(out_dir)
            self.out_dir = out_dir
            # Test if we can write to that directory
            try:
                with open(f"{self.out_dir}/test", "w", encoding='utf-8') as f:
                    f.write("test")
                os.remove(f"{self.out_dir}/test")
            except Exception as e:
                l.critical("[CRITICAL] Output directory %s is probably not writable. Aborting: %s",
                           self.out_dir, e, exc_info=True
                )
                raise
        else:
            self.out_dir = Path(self.covlib_workdir) / 'coverage-results'
            os.makedirs(self.out_dir, exist_ok=True)

        # The name of the harness we want to trace
        # TODO: enforce the existence of this harness
        self.harness_name = harness_name

        # Creating an instance of our coverage fast tracer!
        instrumentation = CoverageFastInstrumentation()
        self.instr_project = InstrumentedOssFuzzProject(
            instrumentation,
            self.target_dir,
        )

        # Build the runner image
        if self.debug_mode:
            self.instr_project.build_runner_image()

        self.language = self.instr_project.project_metadata.language

        assert self.language in [LanguageEnum.jvm], f"Unsupported language {self.language}"

        self.parser = Java_Calltrace_Yajta()

        # The default location of the raw coverage file depending on the language.
        # This default location is defined by oss-fuzz coverage script.
        self.default_raw_coverage_file = self.covlib_done_files_at + "{seed_name}"

        self.parser_internal_cmd = None

        self.BUDDY_TRACER_TIMEOUT_TO_START = 60 * 5

        # This is the buddy tracer that coveragelib is gonna spawn to do on-demand tracing without
        # shutting down the container (until the Tracer object remains in scope)
        self.buddy_tracer: RunImageInBackgroundResult = None

        # There is NO aggregate mode for this tracer.
        self.aggregate = False

        # Are there any extra excludes to add to yajta?
        if extra_excludes:
            # Make sure they are in the form of a list with element separated by
            # a comma
            self.extra_excludes = extra_excludes.split(",")
            self.extra_excludes = [e.strip() for e in self.extra_excludes if e != ' ' and e != '']
        else:
            self.extra_excludes = []
        
        self.all_excludes = 'com.code_intelligence,sun,com.sun'
        for e in self.extra_excludes:
            self.all_excludes += ',' + e


    def __start_background_tracer(self):
        extra_docker_args = ["-e", "FOLDER_TO_MONITOR=" + self.covlib_queue_folder_at]
        extra_docker_args.extend(["-e", "COVLIB_RESULTS=" + self.covlib_results_at])
        extra_docker_args.extend(["-e", "COVLIB_DONE_FILES=" + self.covlib_done_files_at])
        extra_docker_args.extend(["-e", "ASAN_OPTIONS=detect_leaks=0"])
        extra_docker_args.extend(["-e", "YAJTA_COVERAGE=true"])
        extra_docker_args.extend(["-e", "YAJTA_EXCLUDES=" + self.all_excludes])

        if self.parser_internal_cmd:
            extra_docker_args.extend([
                "-e", "SHELLPHISH_PARSING_COMMAND=" + self.parser_internal_cmd
            ])

        if self.aggregate:
            # Wether we want to aggregate the coverage results or having results per seed!
            extra_docker_args.extend(["-e", "COVERAGE_AGGREGATE=true"])
        else:
            extra_docker_args.extend(["-e", "COVERAGE_AGGREGATE=false"])
        
        if self.crash_mode:
            extra_docker_args.extend(["-e", "COVLIB_CRASH_MODE=true"])
        else:
            extra_docker_args.extend(["-e", "COVLIB_CRASH_MODE=false"])

        self.buddy_tracer = self.instr_project.collect_coverage_background_start__local(
                                    self.coverage_harnesses_corpuses_at,
                                    harnesses=[self.harness_name],
                                    extra_docker_args=extra_docker_args
                                    )

    def __enter__(self):
        # This is executed when instantiating the Tracer object
        self.__start_background_tracer()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        # This is executed ALWAYS whenever the Tracer object goes out of scope
        # This is safe in case of exceptions/asserts/etc....

        # First, we need to kill the buddy tracer container
        try:
            subprocess.check_call(["docker", "kill", self.buddy_tracer.container_id])
        except subprocess.CalledProcessError:
            l.warning("[CRITICAL] The buddy tracer container %s could not be killed, maybe it had already died?",
                      self.buddy_tracer.container_id)

        # Second, to avoid resource consumptions, we are gonna remove the container as well
        
        if not self.debug_mode:
            # Second, to avoid resource consumptions, we are gonna remove the container as well
            if exc_type is not None or not artiphishell_should_fail_on_error():
                try:
                    subprocess.check_call(["docker", "rm", "-f", self.buddy_tracer.container_id])
                except subprocess.CalledProcessError:
                    l.warning("[CRITICAL] The buddy tracer container %s could not be removed.", self.buddy_tracer.container_id)
            else:
                l.critical("[CRITICAL] Keeping the container running for debugging purposes | Offending container: %s",
                            self.buddy_tracer)

            # Remove the intermediate folders
            shutil.rmtree(self.covlib_queue_folder_at)
            shutil.rmtree(self.covlib_results_at)
            shutil.rmtree(self.covlib_done_files_at)
            shutil.rmtree(self.coverage_harnesses_corpuses_at)

        return

    def __ensure_tracer_is_alive(self):
        assert self.buddy_tracer
        # Check if the container is still running
        container_state = subprocess.check_output(["docker", "inspect", "--format={{.State.Running}}", self.buddy_tracer.container_id])

        if b"true\n" not in container_state:
            l.critical(f"[CRITICAL] The buddy tracer container seems down during heartbeat check | container_state={container_state}. Aborting.")
            raise BuddyTracerDiedException

    def __wait_for_buddy_tracer_to_be_ready(self):
        start_time = time.time()

        while True:
            if os.path.exists(f"{self.covlib_results_at}/.oss-fuzz-coverage_live.started"):
                break
            elif time.time() - start_time >= self.BUDDY_TRACER_TIMEOUT_TO_START:
                l.critical("[CRITICAL] Timeout reached while waiting for buddy tracer to start | TIMEOUT: %s",
                           self.BUDDY_TRACER_TIMEOUT_TO_START)
                return False
            else:
                self.__ensure_tracer_is_alive()
                time.sleep(1)

    def trace(self, *seeds):
        self.__ensure_tracer_is_alive()
        self.__wait_for_buddy_tracer_to_be_ready()

        # Ensure seeds is always a flattened list
        if len(seeds) == 1 and isinstance(seeds[0], list):
            seeds = seeds[0]  # Unpack the list

        # Sanity check1: Make sure the seeds are unique
        seed_names = [f'seed-{i}' for i in range(len(seeds))]

        log.debug("Seeds: %s, Seed names: %s", seeds, seed_names)
        for i, seed in enumerate(seeds):
            # Sanity check2: Make sure every seed is a file
            if not os.path.isfile(seed):
                l.critical("[CRITICAL] The seed %s is not a file. Aborting", seed)
                raise ValueError
            # Copying it in the queue. This queue is monitored by the watchdog
            # in coverage fast and used as a single-seed corpus to collect
            # coverage information.
            log.debug("Copying seed %s to %s/seed-%s", seed, self.covlib_queue_folder_at, i)
            shutil.copy(seed, Path(self.covlib_queue_folder_at) / f'seed-{i}')

        stop_event = Event()
        event_handler = CovlibResultMonitorHandler(
            self, self.covlib_done_files_at, self.covlib_results_at, self.default_raw_coverage_file, seed_names, stop_event
        )

        observer = PollingObserver(timeout=0.2)
        observer.schedule(event_handler, self.covlib_done_files_at, recursive=False)
        observer.start()

        # create the trigger for the coverage script
        # THIS MUST BE DONE AFTER STARTING THE POLLING OBSERVER
        Path(f"{self.covlib_queue_folder_at}/.covlib.done",).write_bytes(b"done")

        # Wait until we are done!
        stop_event.wait()

        # We are done!
        observer.stop()
        observer.join()

        print(f"[INFO] Coverage results are in {self.out_dir}, took {time.time() - event_handler.monitor_started_at} seconds to trace")

        results = []
        paths_to_parse = [self.out_dir / f'seed-{i}' for i in range(len(seeds))] if not self.aggregate else [self.out_dir / "coverage"]
        for i, out_path in enumerate(paths_to_parse):
            try:
                if self.parser.HAS_VALUE_PARSER:
                    results.append(self.parser.parse_values(self.instr_project, out_path))
                else:
                    results.append(out_path)
            except AttributeError:
                log.exception("[CRITICAL] The parser %s crashed during value parsing. Aborting", self.parser)
                results.append(out_path)
                if artiphishell_should_fail_on_error():
                    raise

        return results

    def trace_dir(self, seed_dir, *args, **kwargs):
        seeds = [os.path.join(seed_dir, f) for f in os.listdir(seed_dir)]
        return self.trace(seeds, *args, **kwargs)
