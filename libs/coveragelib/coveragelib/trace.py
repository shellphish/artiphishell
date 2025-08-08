import logging
import os
import random
import shutil
import string
import subprocess
import tempfile
import threading
import time
import base64
from pathlib import Path
from threading import Event

from coveragelib.parsers.function_coverage import C_FunctionCoverageParser_Profraw, Java_FunctionCoverageParser_Jacoco
from shellphish_crs_utils.models.oss_fuzz import LanguageEnum
from shellphish_crs_utils.models.coverage import SeedCoverageExitStatus
import yaml
from shellphish_crs_utils.models.crs_reports import RunImageInBackgroundResult
from shellphish_crs_utils.oss_fuzz.instrumentation.coverage_fast import \
    CoverageFastInstrumentation
from shellphish_crs_utils.oss_fuzz.project import InstrumentedOssFuzzProject
from shellphish_crs_utils.utils import artiphishell_should_fail_on_error
from watchdog.events import FileSystemEventHandler
from watchdog.observers.polling import PollingObserver
#from watchdog.observers import Observer

from coveragelib import Parser, log

from .errors import BuddyTracerDiedException

l = logging.getLogger("coveragelib")
l.setLevel(logging.INFO)

EXIT_CODE_TO_STATUS = dict()
EXIT_CODE_TO_STATUS['0'] = SeedCoverageExitStatus.SUCCESS
EXIT_CODE_TO_STATUS['233'] = SeedCoverageExitStatus.CRASH
EXIT_CODE_TO_STATUS['124'] = SeedCoverageExitStatus.TIMEOUT
EXIT_CODE_TO_STATUS['234'] = SeedCoverageExitStatus.TIMEOUT

class CovlibResultMonitorHandler(FileSystemEventHandler):
    '''
    This class is a watchdog event handler that is used to monitor the results folder.
    '''
    def __init__(self, tracer, covlib_done_files_at, covlib_results_at, default_raw_coverage_file, seed_names, stop_event):
        self.tracer = tracer
        self.parser = tracer.parser
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

        # This is telling us if the buddy tracer died while we were monitoring for results
        self.buddy_tracer_died = False

    def run_periodically(self):
        '''
        This function makes sure the tracer docker container stays up.
        '''
        while not self.stop_event.is_set():
            try:
                self.tracer._Tracer__ensure_tracer_is_alive()
            except BuddyTracerDiedException:
                l.critical("[CRITICAL] The buddy tracer container died during results monitoring. Aborting.")
                self.buddy_tracer_died = True
                self.stop_event.set()
            time.sleep(2)  # Wait 2 seconds before running again

    # NOTE: because of the polling observer, we are getting "moved" events instead of "created" events sometimes.
    #       Therefore, we need to catch both the events and redirect them to do_stuff.
    #       Given a single seed, it will either pass to the "moved" event OR the "created" event.
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

            # If the size of the file at the src_path is 0, we are gonna ignore it
            # and raise a warning
            if os.path.getsize(cov_file_path) == 0:
                l.warning("[WARNING] The coverage file %s is empty", cov_file_path)

            if self.parser.HAS_EXTERNAL_PROCESSING:
                try:
                    result_at = self.parser.parse(cov_file_path)
                    # Move the result to the results directory
                    shutil.move(result_at, self.tracer.out_dir / os.path.basename(cov_file_path))
                    # Delete the canary file too!
                    os.remove(src_path)
                except Exception as e:
                    log.exception("[CRITICAL] Error while using external processing for seed %s: %s", cov_file_path, e, exc_info=True)
                    if artiphishell_should_fail_on_error():
                        raise
            else:
                shutil.move(cov_file_path, self.tracer.out_dir / os.path.basename(cov_file_path))
                # Delete the canary file too!
                os.remove(src_path)
            
            self.tracer.num_traced_seeds += 1

        if len(self.worklist) == 0:
            self.stop_event.set()



MYROCO_CONFIG_TEMPLATE = '''"instrument_only": "":
"insclasspattern": "<CLASSES_IN_SCOPE>"
"input_watchdir": "/corpus/<HARNESS_NAME>"
"exec_folder": "/out/dumps/"
"dump_dir": "<DUMP_CLASSES_FOLDER>"
'''

class Tracer:
    def __init__(
        self,
        target_dir : Path,
        harness_name : str,
        out_dir=None,
        parser=None,
        aggregate=False,
        timeout_per_seed=100,
        debug_mode = False,
        include_seeds_metadata = False
    ):  

        self.debug_mode = debug_mode
        self.include_seeds_metadata  = include_seeds_metadata
        self.harness_name = harness_name
        self.target_dir = Path(target_dir).resolve()
        self.aggregate = aggregate
        self.timeout_per_seed = timeout_per_seed
        self.num_traced_seeds = 0
        self.buddy_tracer_is_running = False
        self.curr_seeds = []
        self.queue_backup_folder = None

        ########################
        # SANITIY CHECKS 🩺
        ########################
        # The target dir MUST be in /shared/
        assert str(self.target_dir).startswith("/shared/")
        # To make sure the user is giving us an oss-fuzz-dir
        # we are gonna assert that the folder "artifacts"
        self.artifacts_path = os.path.join(self.target_dir, "artifacts")
        assert os.path.isdir(self.artifacts_path)
        self.harness_path = os.path.join(self.artifacts_path, "out", self.harness_name)
        assert os.path.isfile(self.harness_path), f"The harness {self.harness_name} does not exist in the target directory {self.target_dir}: {self.harness_path}"
        ########################

        # If this is the first time we are tracing this project and harness, we want to
        # create the folder for the corpus
        self.__create_covlib_workdir()

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

        # Creating an instance of our coverage fast tracer!
        instrumentation = CoverageFastInstrumentation()
        self.instr_project = InstrumentedOssFuzzProject(
            instrumentation,
            self.target_dir,
        )

        # Build the runner image
        if self.debug_mode:
            self.instr_project.build_runner_image()
        # ^^^^ This is commented out to catch pipeline issues early, talk to Lukas if you disagree with this.

        self.language = self.instr_project.project_metadata.language
        assert self.language in [LanguageEnum.c, LanguageEnum.cpp, LanguageEnum.jvm], f"Unsupported language {self.language}"

        if self.language in [LanguageEnum.c, LanguageEnum.cpp]:
            # Check if the harness is actually compiled with coverage!
            with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmpfile:
                subprocess.check_call(["strings", self.harness_path], stdout=tmpfile)
            # Expect to se __llvm_covmap in the file
            with open(tmpfile.name, "rb") as f:
                if b"__llvm_covmap" not in f.read():
                    l.critical("[CRITICAL] The harness %s is not compiled with coverage. Aborting",
                               harness_name)
                    assert False
            # Remove the temporary file
            os.remove(tmpfile.name)

        if not parser:
            # If the user didn't specify a parser, we are gonna use the default one
            # for the language
            if self.language in [LanguageEnum.c, LanguageEnum.cpp]:
                self.parser = C_FunctionCoverageParser_Profraw()
            else:
                self.parser = Java_FunctionCoverageParser_Jacoco()
        else:
            # make sure the specified parser supports the project's language
            assert self.language in parser.LANGUAGES, \
                f"The parser's languages must support the project's language | Parser: {parser.LANGUAGES} | Project: {self.language}"

            # Instantiate a parser for that class
            assert isinstance(parser, Parser)
            self.parser = parser

        # The default location of the raw coverage file depending on the language.
        # This default location is defined by oss-fuzz coverage script.
        self.default_raw_coverage_file = self.covlib_done_files_at + "{seed_name}"

        # Install the INTERNAL_COMMAND if the parser has one
        # This is the command that gets executed inside the coverage container to perform
        # more complex processing of the coverage data.
        if self.parser.HAS_INTERNAL_COMMAND:
            extra_vars = {
                'harness_name': self.harness_name,
                'target_dir': self.target_dir,
            }
            self.parser_internal_cmd = self.parser.get_internal_cmd(extra_vars=extra_vars)
        else:
            self.parser_internal_cmd = None

        self.BUDDY_TRACER_TIMEOUT_TO_START = 60 * 5

        # This is the buddy tracer that coveragelib is gonna spawn to do on-demand tracing without
        # shutting down the container (until the Tracer object remains in scope)
        self.buddy_tracer: RunImageInBackgroundResult = None

    def __create_covlib_workdir(self):
        self.covlib_workdir = f'{self.target_dir}/artifacts/work/coveragelib-' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
        print(f'Covlib workdir: {self.covlib_workdir}')
        self.covlib_queue_folder_at = f'{self.covlib_workdir}/seeds-queue'
        self.coverage_harnesses_corpuses_at = self.covlib_workdir  + '/corpus/'
        self.coverage_harness_corpus_at = f"{self.coverage_harnesses_corpuses_at}/{self.harness_name}"
        self.covlib_results_at = self.covlib_workdir + '/raw-results/'
        self.covlib_done_files_at = self.covlib_workdir + '/raw-results-done-files/'
        
        # The queue_backup_folder will hold a copy of the covlib_queue_folder_at (in case we fail we want to base64 those)
        # This is safe because we don't know where the seeds will be located 
        #   e.g., if they are in /tmp, they might be removed before we are able to base64 them!
        self.queue_backup_folder = f"/shared/covlib-trace-seeds-backup/queue-backup-{''.join(random.choices(string.ascii_lowercase + string.digits, k=12))}"

        if not str(self.covlib_workdir).startswith("/shared/"):
            raise Exception(f"Covlib workdir {self.covlib_workdir} must be in /shared/. Most likely you target dir {self.target_dir} is wrong!")

        os.makedirs(self.covlib_workdir, exist_ok=True)
        os.makedirs(self.covlib_queue_folder_at, exist_ok=True)
        os.makedirs(self.coverage_harnesses_corpuses_at, exist_ok=True)
        os.makedirs(self.coverage_harness_corpus_at, exist_ok=True)
        os.makedirs(self.covlib_results_at, exist_ok=True)
        os.makedirs(self.covlib_done_files_at, exist_ok=True)
        os.makedirs("/shared/covlib-trace-seeds-backup", exist_ok=True)
        os.makedirs(self.queue_backup_folder, exist_ok=True)

        self.default_raw_coverage_file = self.covlib_done_files_at + "{seed_name}"


    def __start_background_tracer(self):
        extra_docker_args = ["-e", "FOLDER_TO_MONITOR=" + self.covlib_queue_folder_at]
        extra_docker_args.extend(["-e", "COVLIB_RESULTS=" + self.covlib_results_at])
        extra_docker_args.extend(["-e", "COVLIB_DONE_FILES=" + self.covlib_done_files_at])
        extra_docker_args.extend(["-e", "ASAN_OPTIONS=detect_leaks=0"])
        extra_docker_args.extend(["-e", "TIMEOUT_PER_SEED=" + str(self.timeout_per_seed)])

        if self.parser_internal_cmd:
            extra_docker_args.extend([
                "-e", "SHELLPHISH_PARSING_COMMAND=" + self.parser_internal_cmd
            ])

        if self.language == LanguageEnum.jvm and not self.aggregate:
            # If we are using the aggregate mode, there is no need to use Myroco.
            extra_docker_args.extend(["-e", "MYROCO_COVERAGE=true"])
            # Template the config with the name of the harness
            myrococonf = MYROCO_CONFIG_TEMPLATE.replace("<HARNESS_NAME>", self.harness_name)
            myrococonf = myrococonf.replace("<DUMP_CLASSES_FOLDER>", f"/out/dumps/{self.harness_name}_classes")
            # Save the MYROCO_CONFIG in a file
            with open(f"{self.covlib_workdir}/myroco.config", "w", encoding='utf-8') as f:
                f.write(myrococonf)
            extra_docker_args.extend(["-e", f"MYROCO_CONFIG={self.covlib_workdir}/myroco.config"])

        if self.aggregate:
            # Wether we want to aggregate the coverage results or having results per seed!
            extra_docker_args.extend(["-e", "COVERAGE_AGGREGATE=true"])
        else:
            extra_docker_args.extend(["-e", "COVERAGE_AGGREGATE=false"])

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
            shutil.rmtree(self.queue_backup_folder)
            
            # Wipe metadatas
            metadatas = []
            exit_code_metadata_at = os.path.join(self.target_dir, "artifacts", "out", "logs", "seeds_status_logs.txt")
            per_seed_tracing_time_at = os.path.join(self.target_dir, "artifacts", "out", "logs", "per_seeds_tracing_time.txt")
            all_seeds_tracing_time_at = os.path.join(self.target_dir, "artifacts", "out", "logs", "all_seeds_tracing_time.txt")
            metadatas.append(exit_code_metadata_at)
            metadatas.append(per_seed_tracing_time_at)
            metadatas.append(all_seeds_tracing_time_at)
            for metadata_at in metadatas:
                if os.path.exists(metadata_at):
                    # Remove the seeds metadata file
                    # This is to avoid confusion for the next run
                    os.remove(metadata_at)

        # If we were using Myroco, let's restore the original java driver
        if self.language == LanguageEnum.jvm and not self.aggregate:
            # If we were using myroco, there MUST be jazzer_driver-original and jazzer_agent_deploy-original.jar
            # otherwise something went terribly wrong
            target_out_dir = os.path.join(self.target_dir, "artifacts", "out")

            # Compute the path of the original drivers. 
            # NOTE: These copies are done by the oss-fuzz-coverage-live script
            jd_original = os.path.join(target_out_dir, "jazzer_driver-original")
            jad_original = os.path.join(target_out_dir, "jazzer_agent_deploy-original.jar")
            
            # If they don't exist, something is terribly wrong, we should die.
            assert(os.path.exists(jd_original))
            assert(os.path.exists(jad_original))

            jd_myroco = os.path.join(target_out_dir, "jazzer_driver")
            jad_myroco = os.path.join(target_out_dir, "jazzer_agent_deploy.jar")

            # Remove the current jazzer_driver and jazzer_agent_deploy.jar
            subprocess.check_call(["rm", jd_myroco])
            subprocess.check_call(["rm", jad_myroco])

            # Restore the original ones
            subprocess.check_call(["mv", jd_original, os.path.join(target_out_dir, "jazzer_driver")])
            subprocess.check_call(["mv", jad_original, os.path.join(target_out_dir, "jazzer_agent_deploy.jar")])

        return

    def __ensure_tracer_is_alive(self):
        assert self.buddy_tracer

        # Check if the container is still running
        container_state = subprocess.check_output(["docker", "inspect", "--format={{.State.Running}}", self.buddy_tracer.container_id])
        
        if b"true\n" not in container_state:
            l.critical(f"[CRITICAL] The buddy tracer container seems down during heartbeat check | container_state={container_state}. Aborting.")
            l.critical(" - Generating component crash report...")

            docker_inspect = subprocess.check_output(["docker", "inspect", self.buddy_tracer.container_id])
            last_traced_seeds_base64 = self.__debug_only_encode_seeds()
            docker_logs = subprocess.check_output(["docker", "logs", self.buddy_tracer.container_id])
            
            # Let's print the latest logs of the harness execution
            harness_out_logs_path = os.path.join(self.target_dir, "artifacts", "out", "logs", self.harness_name + ".log")
            with open(harness_out_logs_path, "r", encoding='utf-8') as f:
                harness_logs = f.readlines()
            
            DIAGNOSTIC_REPORT =  "\n=======================================================\n"
            DIAGNOSTIC_REPORT += "=================[COVLIB CRASH REPORT]=================\n"
            DIAGNOSTIC_REPORT += "=======================================================\n"
            DIAGNOSTIC_REPORT += "=======================================================\n"
            DIAGNOSTIC_REPORT += "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n"
            DIAGNOSTIC_REPORT += "\n### TRACER STATS:\n"
            DIAGNOSTIC_REPORT += f" - Total traced seeds: {self.num_traced_seeds}\n"
            DIAGNOSTIC_REPORT += "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n"
            DIAGNOSTIC_REPORT += "\n### FULL DOCKER INSPECT OUTPUT:\n"
            DIAGNOSTIC_REPORT += "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n"
            DIAGNOSTIC_REPORT += docker_inspect.decode('utf-8')
            DIAGNOSTIC_REPORT += "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n"
            DIAGNOSTIC_REPORT += "\n### FULL DOCKERLOGS OUTPUT:\n"
            DIAGNOSTIC_REPORT += "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n"
            DIAGNOSTIC_REPORT += docker_logs.decode('utf-8')
            DIAGNOSTIC_REPORT += "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n"
            DIAGNOSTIC_REPORT += "\n### HARNESS OUTPUT LOGS:\n"
            DIAGNOSTIC_REPORT += "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n"
            DIAGNOSTIC_REPORT += "".join(harness_logs)
            DIAGNOSTIC_REPORT += "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n"
            DIAGNOSTIC_REPORT += "\n### LAST SEED/S (base64 encoded):\n"
            for seed_id, seed in enumerate(last_traced_seeds_base64):
                DIAGNOSTIC_REPORT += f" -Seed-{seed_id}:\n{seed}\n"
            DIAGNOSTIC_REPORT += "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n"
            DIAGNOSTIC_REPORT += "=======================================================\n"
            DIAGNOSTIC_REPORT += "=======================================================\n"
            DIAGNOSTIC_REPORT += "=======================================================\n"

            l.critical(DIAGNOSTIC_REPORT)

            self.buddy_tracer_is_running = False
            raise BuddyTracerDiedException

    def __wait_for_buddy_tracer_to_be_ready(self):
        start_time = time.time()

        while True:
            if os.path.exists(f"{self.covlib_results_at}/.oss-fuzz-coverage_live.started"):
                self.buddy_tracer_is_running = True
                break
            elif time.time() - start_time >= self.BUDDY_TRACER_TIMEOUT_TO_START:
                l.critical("[CRITICAL] Timeout reached while waiting for buddy tracer to start | TIMEOUT: %s",
                           self.BUDDY_TRACER_TIMEOUT_TO_START)
                self.buddy_tracer_is_running = False
                return False
            else:
                self.__ensure_tracer_is_alive()
                time.sleep(1)

    def __debug_only_encode_seeds(self):
        seeds_base64 = []
        # For every seed in the folder, base64 encode it 
        for seed in self.curr_seeds:
            with open(seed, "rb") as f:
                data = f.read()
                encoded_data = base64.b64encode(data).decode("utf-8")
            seeds_base64.append(encoded_data)
        return seeds_base64

    def __is_tracer_locked(self):
        # Check if the .covlib_tracer_locked file exists
        return os.path.exists(f"{self.target_dir}/artifacts/out/.covlib_tracer_locked")
    
    def __lock_tracer(self):
        # Create a .covlib_tracer_locked file in the 
        # /out directory of the target 
        with open(f"{self.target_dir}/artifacts/out/.covlib_tracer_locked", "w", encoding='utf-8') as f:
            f.write("*")
    
    def __unlock_tracer(self):
        # Remove the .covlib_tracer_locked file
        os.remove(f"{self.target_dir}/artifacts/out/.covlib_tracer_locked")

    def restart(self):
        # If the buddy tracer is alive, let's kill it
        if self.buddy_tracer:
            container_state = subprocess.check_output(["docker", "inspect", "--format={{.State.Running}}", self.buddy_tracer.container_id])
            
            if b"true\n" in container_state:
                assert self.buddy_tracer_is_running
                # WARNING: This is killing a running tracer...
                l.warning(f"[WARNING] You are restarting a RUNNING buddy tracer!")
                l.warning(f"[WARNING] The buddy tracer container {self.buddy_tracer.container_id} is still running, killing it to restart...")
                try:
                    subprocess.check_call(["docker", "kill", self.buddy_tracer.container_id])
                except subprocess.CalledProcessError:
                    l.warning(f"[WARNING] The buddy tracer container {self.buddy_tracer.container_id} could not be killed?")
                    l.warning(f"  - Assuming it already died...")
                    self.buddy_tracer_is_running = False
                if not self.debug_mode:
                    try:
                        subprocess.check_call(["docker", "rm", "-f", self.buddy_tracer.container_id])
                    except subprocess.CalledProcessError:
                        l.warning("[CRITICAL] The buddy tracer container %s could not be removed.", self.buddy_tracer.container_id)


            # Remove the .oss-fuzz-coverage_live.started
            # file if it exists (this is a canary file created by the oss-fuzz-coverage-live script)
            if os.path.exists(f"{self.covlib_results_at}/.oss-fuzz-coverage_live.started"):
                os.remove(f"{self.covlib_results_at}/.oss-fuzz-coverage_live.started")
                
            # Stop the monitor if it was still running
            try:
                self.covlib_res_monitor.stop_event.set()
                self.covlib_res_monitor.stop_event.wait()
                self.observer.stop()
                self.observer.join()
                self.observer.unschedule_all()
            except Exception as e:
                l.warning(f"[WARNING] Could not stop the observer: {e}. Continuing...")

            self.buddy_tracer_is_running = False
            self.buddy_tracer: RunImageInBackgroundResult = None
            self.observer = None
            self.num_traced_seeds = 0
            self.curr_seeds = []

            dirs_to_wipe = []
            dumps_dir = os.path.join(self.artifacts_path, "out", "dumps")
            logs_dir = os.path.join(self.artifacts_path, "out", "logs")
            fuzzer_stats_dir = os.path.join(self.artifacts_path, "out", "fuzzer_stats")
            textcov_report_dir = os.path.join(self.artifacts_path, "out", "textcov_reports")

            if os.path.exists(dumps_dir):
                dirs_to_wipe.append(dumps_dir)
            if os.path.exists(logs_dir):
                dirs_to_wipe.append(logs_dir)
            if os.path.exists(fuzzer_stats_dir):
                dirs_to_wipe.append(fuzzer_stats_dir)
            if os.path.exists(textcov_report_dir):
                dirs_to_wipe.append(textcov_report_dir)
            if os.path.exists(self.queue_backup_folder):
                dirs_to_wipe.append(self.queue_backup_folder)

            # Wipe the out_dir if it still exists (i.e., the user passed a different one not in
            # in the covlib_workdir)
            if os.path.exists(self.out_dir):
                shutil.rmtree(self.out_dir)

            for dir_to_wipe in dirs_to_wipe:
                l.info(f"Wiping directory {dir_to_wipe}")
                try:
                    shutil.rmtree(dir_to_wipe)
                except Exception as e:
                    l.warning(f"[WARNING] Could not wipe directory {dir_to_wipe}: {e}. Continuing...")

            # Wipe the self.covlib_workdir and recreate it 
            old_covlib_workdir = Path(self.covlib_workdir)
            shutil.rmtree(self.covlib_workdir)

            self.__create_covlib_workdir()

            # If the self.out_dir was within /work/coveragelib-
            # Then we create it from scratch 
            if self.out_dir.is_relative_to(old_covlib_workdir):
                self.out_dir = Path(self.covlib_workdir) / 'coverage-results'
                os.makedirs(self.out_dir, exist_ok=True)
            else:
                # This was defined from the user, let's just re-create it.
                os.makedirs(self.out_dir, exist_ok=True)

            # - Remove the lock file in /artifacts/out/.
            if self.__is_tracer_locked():
                self.__unlock_tracer()

            # Now it's time to restart the tracer!
            try:
                self.__start_background_tracer()
            except Exception as e:
                l.critical(f"[CRITICAL] Could not restart the buddy tracer: {e}. This is a bug, ping @degrigis...")
                self.buddy_tracer_is_running = False
                raise AssertionError
        else:
            l.warning("[WARNING] The buddy tracer was never started, nothing to restart")
            l.warning(" - This is kinda weird, ping @degrigis...")

    def trace(self, *seeds):
        if self.__is_tracer_locked():
            raise Exception(f"This target folder [{self.target_dir}] is already locked by a Tracer!\n You can manually remove the lock by deleting the file at {self.target_dir}/artifacts/out/.covlib_tracer_locked")
        else:
            self.__lock_tracer()

        self.__ensure_tracer_is_alive()
        self.__wait_for_buddy_tracer_to_be_ready()

        # Ensure seeds is always a flattened list
        if len(seeds) == 1 and isinstance(seeds[0], list):
            seeds = seeds[0]  # Unpack the list

        if len(seeds) == 0:
            self.__unlock_tracer()
            raise ValueError("You must provide at least one seed to trace!")
        print(f"Tracing {len(seeds)} seeds | aggregate_mode={self.aggregate}")

        # Sanity check1: Make sure the seeds are unique
        seed_names = [f'seed-{i}' for i in range(len(seeds))]

        log.debug("Seeds: %s, Seed names: %s", seeds, seed_names)
        for i, seed in enumerate(seeds):
            # Sanity check2: Make sure every seed is a file
            if not os.path.isfile(seed):
                l.critical("[CRITICAL] The seed %s is not a file. Aborting", seed)
                self.__unlock_tracer()
                raise ValueError
            # Copying it in the queue. This queue is monitored by the watchdog
            # in coverage fast and used as a single-seed corpus to collect
            # coverage information.
            log.debug("Copying seed %s to %s/seed-%s", seed, self.covlib_queue_folder_at, i)
            # Copy the seed in the folder monitored by the oss-fuzz-coverage_live
            shutil.copy(seed, Path(self.covlib_queue_folder_at) / f'seed-{i}')
            # Copy the seed also in the queue backup (so we can do diagnostic later if something goes wrong)
            # shutil.copy(seed, Path(self.queue_backup_folder) / f'seed-{i}')
            # Store a reference of the current seed we are working on
            self.curr_seeds.append(Path(self.queue_backup_folder) / f'seed-{i}')

        if not self.aggregate:
            # Now start to monitor the results folder for the coverage files
            stop_event = Event()
            self.covlib_res_monitor = CovlibResultMonitorHandler(
                self, self.covlib_done_files_at, self.covlib_results_at, self.default_raw_coverage_file, seed_names, stop_event
            )
        else:
            # For aggregate mode, we ware waiting only for the file named "coverage"
            seed_names = ["coverage"]
            stop_event = Event()
            self.covlib_res_monitor = CovlibResultMonitorHandler(
                self, self.covlib_done_files_at, self.covlib_results_at, self.default_raw_coverage_file, seed_names, stop_event
            )

        # NOTE: DO NOT change this to the inotify observer: We are hitting MAX numbers in the CRS.
        self.observer = PollingObserver(timeout=0.2)
        
        # NOTE: we are monitoring the folder where the oss-fuzz-coverage_live script is going
        #       to write a canary file to signal the end of the coverage collection for a seed (I called them "done files").
        #       This will ensure that the actual file containing the results have been completely written on disk before accessing it.
        self.observer.schedule(self.covlib_res_monitor, self.covlib_done_files_at, recursive=False)
        self.observer.start()

        # create the trigger for the coverage script
        # THIS MUST BE DONE AFTER STARTING THE POLLING OBSERVER
        Path(f"{self.covlib_queue_folder_at}/.covlib.done",).write_bytes(b"done")

        # Wait until we are done! 
        stop_event.wait()

        # We are done!
        self.observer.stop()
        self.observer.join()
        self.observer.unschedule_all()

        # DIE IF THE BUDDY TRACER DIED
        if self.covlib_res_monitor.buddy_tracer_died:
            self.buddy_tracer_is_running = False
            raise BuddyTracerDiedException

        print(f"[INFO] Coverage results are in {self.out_dir}, took {time.time() - self.covlib_res_monitor.monitor_started_at} seconds to trace")
        print(f"   - NOTE: this is the end-to-end time since we started the CoverageResultsMonitor worker until we saw THE LAST result appearing from the buddy tracer!")

        results = []
        paths_to_parse = [self.out_dir / f'seed-{i}' for i in range(len(seeds))] if not self.aggregate else [self.out_dir / "coverage"]
        
        value_parsing_times = {}
        for i, out_path in enumerate(paths_to_parse):
            seed_name = f'seed-{i}' if not self.aggregate else "coverage"
            try:
                start_time_value_parsing = time.time()
                if self.parser.HAS_VALUE_PARSER:
                    results.append(self.parser.parse_values(self.instr_project, out_path))
                else:
                    results.append(out_path)
            except AttributeError:
                log.exception("[CRITICAL] The parser %s crashed during value parsing. Aborting", self.parser)
                results.append(out_path)
                if artiphishell_should_fail_on_error():
                    raise
            finally:
                value_parsing_times[seed_name] = time.time() - start_time_value_parsing

        if self.include_seeds_metadata:
            if self.aggregate:
                metadata_at = os.path.join(self.target_dir, "artifacts", "out", "logs", "all_seeds_tracing_time.txt")
            else:
                metadata_at = os.path.join(self.target_dir, "artifacts", "out", "logs", "per_seeds_tracing_time.txt")

            if os.path.exists(metadata_at):
                with open(metadata_at, "r", encoding='utf-8') as f:
                    seeds_metadata = f.readlines()
                seeds_metadata = [line.strip() for line in seeds_metadata]
                # Remove the file after reading it (so it's available for the next call)
                os.remove(metadata_at)
            else:
                seeds_metadata = []
            
            # Read status codes into metadata
            exit_code_metadata_at = os.path.join(self.target_dir, "artifacts", "out", "logs", "seeds_status_logs.txt")
            exit_code_dict = {}
            if os.path.exists(exit_code_metadata_at):
                with open(exit_code_metadata_at, "r", encoding='utf-8') as f:
                    exit_codes = f.readlines()
                exit_codes = [line.strip() for line in exit_codes]
                for exit_code in exit_codes:
                    seed_name = exit_code.split(" ")[0]
                    code = exit_code.split(" ")[1]
                    exit_code_dict[seed_name] = int(code)
                # Remove the file after reading it (so it's available for the next call)
                os.remove(exit_code_metadata_at)
            else:
                exit_code_dict = {}
            # We don;t have exit code when in aggregate mode
            if self.aggregate:
                exit_code_dict["all_seeds_tracing_time"] = None

            # Process the seeds metadata
            seed_meta_json_report = dict()
            for seed_meta in seeds_metadata:
                seed_name, tracing_time = seed_meta.split(" ")
                seed_meta_json_report[seed_name] = {}
                seed_meta_json_report[seed_name]['tracing_time'] = float(tracing_time)
                if self.aggregate:
                    value_parsing_time = value_parsing_times.get("coverage", 0.0)
                else:
                    value_parsing_time = value_parsing_times.get(seed_name, 0.0)
                seed_meta_json_report[seed_name]['parsing_time'] = float(value_parsing_time)
                if exit_code_dict.get(seed_name) is not None:
                    seed_meta_json_report[seed_name]['exit_code'] = exit_code_dict[seed_name]
        if self.aggregate:
            results, = results

        assert self.__is_tracer_locked(), "The tracer should be locked at this point..."
        self.__unlock_tracer()

        if self.include_seeds_metadata:
            return results, seed_meta_json_report
        else:
            return results

    def trace_dir(self, seed_dir, *args, **kwargs):
        seeds = [os.path.join(seed_dir, f) for f in os.listdir(seed_dir)]
        return self.trace(*seeds, *args, **kwargs)
