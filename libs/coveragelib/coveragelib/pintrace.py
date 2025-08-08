import fcntl
import logging
import os
import random
import shutil
import string
import subprocess
import hashlib
import tempfile
import threading
import time
from pathlib import Path
from threading import Event
from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject

from coveragelib.parsers.calltrace_coverage import C_Calltrace_PinTracer, C_Indirect_PinTracer, C_Calltrace_Json_PinTracer
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

from shellphish_crs_utils import ARTIPHISHELL_DIR, LIBS_DIR, C_INSTRUMENTATION_DIR, BLOBS_DIR

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
        self.scheduler_thread = threading.Thread(
            target=self.run_periodically, daemon=True)
        self.scheduler_thread.start()

    def run_periodically(self):
        '''
        This function makes sure the tracer docker container stays up.
        '''
        while not self.stop_event.is_set():
            try:
                self.tracer._Pintracer__ensure_tracer_is_alive()
            except AssertionError:
                l.critical(
                    "[CRITICAL] The buddy tracer container is not running. Aborting.")
                self.stop_event.set()
            time.sleep(2)  # Wait 2 seconds before running again

    def on_moved(self, event):
        # The polling observer is creating "moved" events instead of "created" events, which is causing issues.
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
            cov_file_path = os.path.join(
                self.covlib_results_at, os.path.basename(src_path))
            print(f"Expecting coverage file {cov_file_path}")

            # If the size of the file at the cov_file_path is 0, we are gonna ignore it
            # and raise a warning
            if os.path.getsize(cov_file_path) == 0:
                l.warning(
                    "[WARNING] The coverage file %s is empty", cov_file_path)

            shutil.move(cov_file_path, self.tracer.out_dir /
                        os.path.basename(cov_file_path))
            os.remove(src_path)

        if len(self.worklist) == 0:
            self.stop_event.set()


class Pintracer:
    def __init__(
        self,
        target_dir: Path,
        harness_name: str,
        out_dir=None,
        full_function_mode=True,
        trace_inlines=False,
        aggregate=False,
        debug_mode=False,
        return_func_json=False
    ):

        # NOTE: If by mistake someone passes the aggregate=True, we are gonna ignore it.
        if aggregate == True:
            print(
                "[WARNING] The aggregate option is not supported by the Pintracer. Setting it to False.")
        self.aggregate = False
        # default: this traces functions with no indirect jumps
        self.full_function_mode = full_function_mode
        self.trace_inlines = trace_inlines
        self.debug_mode = debug_mode
        target_dir = Path(target_dir).resolve()

        # The target dir MUST be in /shared/
        assert str(target_dir).startswith("/shared/")

        # To make sure the user is giving us an oss-fuzz-dir
        # we are gonna assert that the folder "artifacts"
        artifacts_path = os.path.join(target_dir, "artifacts")
        assert os.path.isdir(artifacts_path)
        harness_path = os.path.join(artifacts_path, "out", harness_name)
        assert os.path.isfile(
            harness_path), f"The harness {harness_name} does not exist in the target directory {target_dir}"

        # If this is the first time we are tracing this project and harness, we want to
        # create the folder for the corpus
        # Generate a temporary name for the corpus
        self.covlib_workdir = f'{target_dir}/artifacts/work/coveragelib-' + \
            ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
        self.covlib_queue_folder_at = f'{self.covlib_workdir}/seeds-queue'
        self.coverage_harnesses_corpuses_at = self.covlib_workdir + '/corpus/'
        self.coverage_harness_corpus_at = f"{self.coverage_harnesses_corpuses_at}/{harness_name}"
        self.covlib_results_at = self.covlib_workdir + '/raw-results/'
        self.covlib_done_files_at = self.covlib_workdir + '/raw-results-done-files/'

        os.makedirs(self.coverage_harness_corpus_at, exist_ok=True)
        os.makedirs(self.covlib_results_at, exist_ok=True)
        os.makedirs(self.covlib_queue_folder_at, exist_ok=True)
        os.makedirs(self.covlib_done_files_at, exist_ok=True)

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

        assert self.language in [
            LanguageEnum.c, LanguageEnum.cpp], f"Unsupported language {self.language}"
        self.return_func_json = return_func_json
        if self.full_function_mode:
            if self.return_func_json:
                self.parser = C_Calltrace_Json_PinTracer()
            else:
                self.parser = C_Calltrace_PinTracer()
        else:
            self.parser = C_Indirect_PinTracer()

        # The default location of the raw coverage file depending on the language.
        # This default location is defined by oss-fuzz coverage script.
        self.default_raw_coverage_file = self.covlib_done_files_at + \
            "{seed_name}"

        self.parser_internal_cmd = None

        self.BUDDY_TRACER_TIMEOUT_TO_START = 60 * 5

        # This is the buddy tracer that coveragelib is gonna spawn to do on-demand tracing without
        # shutting down the container (until the Tracer object remains in scope)
        self.buddy_tracer: RunImageInBackgroundResult = None

    def __start_background_tracer(self):
        extra_docker_args = [
            "-e", "FOLDER_TO_MONITOR=" + self.covlib_queue_folder_at]
        extra_docker_args.extend(
            ["-e", "COVLIB_RESULTS=" + self.covlib_results_at])
        extra_docker_args.extend(
            ["-e", "COVLIB_WORKDIR=" + self.covlib_workdir])
        extra_docker_args.extend(["-e", "ASAN_OPTIONS=detect_leaks=0"])
        extra_docker_args.extend(["-e", "PINTRACER_COVERAGE=true"])
        extra_docker_args.extend(["-e", "COVERAGE_AGGREGATE=false"])
        extra_docker_args.extend(
            ["-e", "COVLIB_DONE_FILES=" + self.covlib_done_files_at])

        if self.full_function_mode:
            extra_docker_args.extend(["-e", "PINTRACER_FUNCTIONS=1"])
        else:
            extra_docker_args.extend(["-e", "PINTRACER_FUNCTIONS=0"])

        if self.trace_inlines:
            extra_docker_args.extend(["-e", "PINTRACER_INLINES=1"])
        else:
            extra_docker_args.extend(["-e", "PINTRACER_INLINES=0"])

        if self.parser_internal_cmd:
            extra_docker_args.extend([
                "-e", "SHELLPHISH_PARSING_COMMAND=" + self.parser_internal_cmd
            ])

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
        try:
            subprocess.check_call(
                ["docker", "kill", self.buddy_tracer.container_id])
        except subprocess.CalledProcessError:
            l.warning("[CRITICAL] The buddy tracer container %s could not be killed, maybe it had already died?",
                      self.buddy_tracer.container_id)

        if not self.debug_mode:
            # Second, to avoid resource consumptions, we are gonna remove the container as well
            if exc_type is not None or not artiphishell_should_fail_on_error():
                subprocess.check_call(
                    ["docker", "rm", "-f", self.buddy_tracer.container_id])
            else:
                l.critical("[CRITICAL] Keeping the container running for debugging purposes | Offending container: %s",
                           self.buddy_tracer)

            # Remove the intermediate folders
            shutil.rmtree(self.covlib_queue_folder_at)
            shutil.rmtree(self.covlib_results_at)
            shutil.rmtree(self.covlib_done_files_at)
            shutil.rmtree(self.coverage_harnesses_corpuses_at)
            metadata_at = os.path.join(
                self.target_dir, "artifacts", "out", "logs", "seeds_status_logs.txt")
            if os.path.exists(metadata_at):
                # Remove the seeds metadata file
                # This is to avoid confusion for the next run
                os.remove(metadata_at)

        return

    def __ensure_tracer_is_alive(self):
        assert self.buddy_tracer
        # Check if the container is still running
        assert subprocess.check_output(
            ["docker", "inspect", "--format={{.State.Running}}", self.buddy_tracer.container_id]) == b"true\n"

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
                l.critical(
                    "[CRITICAL] The seed %s is not a file. Aborting", seed)
                raise ValueError
            # Copying it in the queue. This queue is monitored by the watchdog
            # in coverage fast and used as a single-seed corpus to collect
            # coverage information.
            log.debug("Copying seed %s to %s/seed-%s",
                      seed, self.covlib_queue_folder_at, i)
            shutil.copy(seed, Path(self.covlib_queue_folder_at) / f'seed-{i}')

        stop_event = Event()
        event_handler = CovlibResultMonitorHandler(
            self, self.covlib_done_files_at, self.covlib_results_at, self.default_raw_coverage_file, seed_names, stop_event
        )

        observer = PollingObserver(timeout=0.2)
        observer.schedule(
            event_handler, self.covlib_done_files_at, recursive=False)
        observer.start()

        # create the trigger for the coverage script
        # THIS MUST BE DONE AFTER STARTING THE POLLING OBSERVER
        Path(f"{self.covlib_queue_folder_at}/.covlib.done",).write_bytes(b"done")

        # Wait until we are done!
        stop_event.wait()

        # We are done!
        observer.stop()
        observer.join()

        print(
            f"[INFO] Coverage results are in {self.out_dir}, took {time.time() - event_handler.monitor_started_at} seconds to trace")

        results = []
        paths_to_parse = [self.out_dir / f'seed-{i}' for i in range(
            len(seeds))] if not self.aggregate else [self.out_dir / "coverage"]
        for i, out_path in enumerate(paths_to_parse):
            try:
                if self.parser.HAS_VALUE_PARSER:
                    results.append(self.parser.parse_values(
                        self.instr_project, out_path))
                else:
                    results.append(out_path)
            except Exception as e:
                log.exception(
                    "[CRITICAL] The parser %s crashed during value parsing. Aborting", self.parser)
                results.append(out_path)
                raise e

        return results

    def trace_dir(self, seed_dir, *args, **kwargs):
        seeds = [os.path.join(seed_dir, f) for f in os.listdir(seed_dir)]
        return self.trace(seeds, *args, **kwargs)


class PintracerWithSanitizer:
    # TODO: aggregate mode for tracing sanitizer-enabled binaries faster

    def create_cmd_file(self, cmd: str, base_path=None):
        timestamp = int(time.time())
        random_bytes = os.urandom(32)
        random_hash = hashlib.sha1(random_bytes).hexdigest()
        command_file_name = f"cmd_{timestamp}_{random_hash}.sh"

        command_file_host = base_path / "artifacts" / "work" / command_file_name
        with open(command_file_host, "w") as f:
            f.write("#!/bin/bash\n")
            f.write(f"set -x\n")
            f.write(f"echo $(pwd)\n")
            f.write(f"{cmd}\n")

        command_file_host.chmod(0o755)
        return command_file_host

    def run_cmd_in_container(self, cmd_file_name: str):
        return

    def __is_tracer_locked(self):
        # Check if the .covlib_tracer_locked file exists
        return os.path.exists(f"{self.project_path}/artifacts/out/.covlib_tracer_locked")

    def __lock_tracer(self):
        # Create a .covlib_tracer_locked file in the
        # /out directory of the target
        with open(f"{self.project_path}/artifacts/out/.covlib_tracer_locked", "w", encoding='utf-8') as f:
            f.write("*")

    def __unlock_tracer(self):
        # Remove the .covlib_tracer_locked file
        os.remove(f"{self.project_path}/artifacts/out/.covlib_tracer_locked")

    def get_inlines(self):
        dwarf_dump_path = "none"
        harness_path = self.harness_path
        self.inlines_path = harness_path + ".inlines"
        utils_dir = (Path(LIBS_DIR) / "coveragelib" / "coveragelib" / "utils").resolve()

        p = subprocess.Popen(
            f"{LIBS_DIR}/coveragelib/coveragelib/utils/get-inlines.sh {harness_path} {self.inlines_path} {utils_dir}",
            shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE
        )
        stdout, stderr = p.communicate()
        if self.debug_mode:
            print("get-inlines.sh stdout:\n", stdout.decode())
            print("get-inlines.sh stderr:\n", stderr.decode())
        p.wait()
        if p.returncode != 0:
            # check why return value is weird
            if not os.path.exists(self.inlines_path) or os.path.getsize(self.inlines_path) < 10:
                print("[ERROR] Inlines retrieval failed, they will not be traced")
                self.trace_inlines = False
        else:
            size_of_inlines = os.path.getsize(self.inlines_path)
            print(f"Inlines retrieved successfully, size: {size_of_inlines} bytes")
            

    def get_functions(self):
        get_functions_cmd = (
            f"nm -C {self.harness_path} | "
            r"grep -E ' (T|t) ' | "
            r"grep -vE '(__sanitizer::|__sanitizer_internal|__sanitizer_cov|__sanitizer_weak|wrapped_qsort|__interception::|___interceptor_|__interceptor_|__cxa_guard|__asan::|__asan_|__lsan::|__lsan_|__ubsan::|__ubsan_|__msan::|__msan_|fuzzer::|__Fuzzer::chrono|std::__Fuzzer::|initializeValueProfRuntimeRecord|writeFileWithoutReturn|__llvm_profile_write_file|lprofSuspendSigKill|__cxxabiv|__cxx_|__cxa|__sanitizer_|__sancov|sancov\.|asan_thread_start|deregister_tm_clones|__do_global_dtors_aux|asan.module_dtor|include\/c++|compiler-rt|\"_init\"|\"_end\")' | "
            "cut -d ' ' -f1 | "
            r"sed -E 's/^0+/0x0/g' | "
            "sort -u"
        )
        p = subprocess.Popen(get_functions_cmd, shell=True, text=True, stdout=open(
            f"{self.harness_path}.functions", "w"))
        rc = p.wait()
        if rc != 0:
            assert False, "Function offsets retrieval failed, dying. Ping @ubersandro."

    def __init__(
        self,
        oss_fuzz_project: OSSFuzzProject = None,
        coverage_oss_fuzz_project: OSSFuzzProject = None,
        harness_name: str = None,
        full_function_mode=True,
        # this must default to true, some functions coming from the stack trace do not show up otherwise
        coverage_build_path=None, 
        sanitizer_build_path=None, # TODO: remove
        trace_inlines=True,
        aggregate=False,  # one day this will be defaulted to True, or possibly removed if the tool expects that there will be a list of seeds to trace
        debug_mode=False,  # this can be used for providing output
        return_func_json=True,  # this will be very likely the default
        use_rio = False
    ):
        assert oss_fuzz_project is not None, "The oss_fuzz_project must be provided"
        assert coverage_oss_fuzz_project is not None, "The coverage_oss_fuzz_project must be provided"
        coverage_build_path = coverage_oss_fuzz_project.project_path
        sanitizer_build_path = oss_fuzz_project.project_path
        assert coverage_build_path is not None, "The coverage_build_path must be provided"
        assert sanitizer_build_path is not None, "The sanitizer_build_path must be provided"
        assert harness_name is not None, "The harness_name must be provided"
        self.use_rio = False # not anymore
        # two projects are needed, one for the sanitizer and one for the coverage (to do the parsing in this latter)
        self.oss_fuzz_project = oss_fuzz_project
        self.coverage_oss_fuzz_project = coverage_oss_fuzz_project
        coverage_build_path = Path(coverage_build_path).resolve()
        coverage_artifacts_path = os.path.join(
            coverage_build_path, "artifacts")
        sanitizer_build_path = Path(sanitizer_build_path).resolve()
        artifacts_path = os.path.join(sanitizer_build_path, "artifacts")

        # NOTE: these are the artifacts of the sanitizer project
        self.artifacts_path = Path(artifacts_path)
        self.project_path = Path(sanitizer_build_path)
        self.coverage_project_path = Path(coverage_build_path)

        # sanity check on what you passed, you never know
        assert os.path.isdir(coverage_artifacts_path)
        assert os.path.isdir(artifacts_path)

        if not use_rio:
        # sanity check on the pintracer
            tmp = os.path.join(coverage_artifacts_path, 'out/pin')
            tmp2 = os.path.join(coverage_artifacts_path,
                                'out/pintracer/fun-q-lo.so')
            assert os.path.isdir(
                tmp), f"The pin folder {tmp} does not exist, make sure that the coverage build was successful and the build artifacts are in the right place"
            assert os.path.isfile(
                tmp2), f"The pintool {tmp2} does not exist, make sure that the coverage build was successful and the build artifacts are in the right place"
            if not os.path.exists(os.path.join(artifacts_path, "out/pin")):
                shutil.copytree(os.path.join(coverage_artifacts_path,
                                "out/pin"), os.path.join(artifacts_path, "out/pin"))

            shutil.copytree(os.path.join(coverage_artifacts_path, "out/pintracer"),
                            os.path.join(artifacts_path, "out/pintracer"), dirs_exist_ok=True)
        else:
            print("[+] Using DynamoRIO backend")
            tmp = os.path.join(coverage_artifacts_path, 'out/dynamorio')
            tmp2 = os.path.join(coverage_artifacts_path,
                                'out/riotracer/libtracer.so')
            assert os.path.isdir(
                tmp), f"The DynamoRIO folder {tmp} does not exist, make sure that the coverage build was successful and the build artifacts are in the right place"
            assert os.path.isfile(
                tmp2), f"The RIO TOOL {tmp2} does not exist, make sure that the coverage build was successful and the build artifacts are in the right place"
            # Only create the directory if it doesn't exist, do not copy the whole tree due to symlinks
            if not os.path.exists(os.path.join(artifacts_path, "out/dynamorio")):
                shutil.copytree(
                    tmp,
                    os.path.join(artifacts_path, "out/dynamorio"),
                    symlinks=True,
                    dirs_exist_ok=True
                )
            
            if not os.path.exists(os.path.join(artifacts_path, "out/riotracer")):
                shutil.copytree(os.path.join(coverage_artifacts_path, "out/riotracer"), os.path.join(artifacts_path, "out/riotracer"), dirs_exist_ok=True)
            
        # sanityc check on the harness you ask me to trace
        harness_path = os.path.join(artifacts_path, "out", harness_name)
        assert os.path.isfile(
            harness_path), f"The harness {harness_path} does not exist"
        self.harness_path = harness_path
        self.harness_name = harness_name

        # what do you want to trace?
        if aggregate:
            print("[+] Aggregate mode enabled")

        self.aggregate = aggregate
        self.full_function_mode = full_function_mode
        self.trace_inlines = trace_inlines
        self.debug_mode = debug_mode
        self.return_func_json = return_func_json

        if self.full_function_mode:
            if self.return_func_json:
                # return results as a list of JSONs/dicts including the symbols called
                self.parser = C_Calltrace_Json_PinTracer()
            else:
                self.parser = C_Calltrace_PinTracer()  # return a list of symbols called
        else:
            assert False, "Indirect branches are not supported by PintracerWithSanitizer yet. Ping @ubersandro if you need this feature."
        self.succeeded = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if not self.succeeded:
            print("[WARNING] The tracer did not succeed, the results are not in the output directory, unlocking the tracer working dir")
            os.remove(
                f"{self.project_path}/artifacts/out/.covlib_tracer_locked")
        return

    def create_cmd_pin(self, seeds, output_prefix):
        cmd = "EXECUTION_ERRORS=0\n"

        for s in seeds:
            seed_name = os.path.basename(s)
            seed_i = f"/work/{seed_name}"
            shutil.copy(s, self.artifacts_path / "work" / seed_name)
            DBG = 1 if self.debug_mode else 0
            SUPPRESS = 0 if self.debug_mode else 1
            # trace
            inlines = '1' if self.trace_inlines else '0'
            TIMEOUT_THRESHOLD = 60

            output = f"{output_prefix}/{seed_name}.out"
            output_json = f"{output_prefix}/{seed_name}.json"

            cmd += f"timeout --preserve-status -s SIGKILL {TIMEOUT_THRESHOLD+10}s /out/pin/pin -follow_execv -t /out/pintracer/fun-q-lo.so -output {output_prefix} -trace_calls 1 -addresses /out/{self.harness_name}.functions -trace_inlined {inlines} -inlines_path /out/{self.harness_name}.inlines -intercept_signals 1 -debug_mode {DBG} -suppress_stdout_stderr {SUPPRESS} -- /out/{self.harness_name} -timeout={TIMEOUT_THRESHOLD} {seed_i}\n"
            cmd += "exit_code=$?\n"
            cmd += "echo \"[DEBUG] Exit code: $exit_code\"\n"
            cmd += "if [ ! $exit_code -eq 0 -a ! $exit_code -eq 1 ]; then\n"
            cmd += f"    echo \"[WARNING] Trace of {seed_i} not correctly produced, creating empty file\";\n"
            cmd += f"    echo -n > {output_json}\n"
            cmd += "else\n"
            cmd += f"   cat {output} | /out/llvm-symbolizer --exe /out/{self.harness_name} --output-style=JSON  | grep -vE \"(compiler-rt|covrec|include/c++|InstrProfilingValue.c|cxa_noexception.cpp)\" > {output_json}\n"
            cmd += "fi\n"
            
            output_on_the_host = str(self.artifacts_path) + f"{output_prefix}/{seed_name}.json"
            self.jsons.append(Path(output_on_the_host).resolve())
        cmd += "if [ $EXECUTION_ERRORS -eq 1 ]; then exit 1337; else exit 0; fi\n"
        return cmd
    
    def create_cmd_rio(self, seeds, output_prefix):
        cmd = ""
        for s in seeds:
            seed_name = os.path.basename(s)
            seed_i = f"/work/{seed_name}"
            shutil.copy(s, self.artifacts_path / "work" / seed_name)
            
            # export outfile name to env
            output = f"{output_prefix}/{seed_name}.out"
            cmd +=f"export DRTOOL_OUTFILE={output}\n"
            
            # concat offset files and export it to RIO
            offsets_file = "/out/offsets.txt"
            cmd +=f"cat /out/{self.harness_name}.functions /out/{self.harness_name}.inlines > {offsets_file}\n"
            cmd +=f"export OFFSETS_FILE={offsets_file}\n"

            # inlines always traced with RIO
            cmd += f"/out/dynamorio/bin64/drrun -c /out/riotracer/libtracer.so -no-follow-child -- /out/{self.harness_name} {seed_i} || true\n"
            # then unset
            cmd += "unset DRTOOL_OUTFILE\n"
            cmd += "unset OFFSETS_FILE\n"
            
            # symbolize
            
            output_json = f"{output_prefix}/{seed_name}.json"
            cmd += f"cat {output} | /out/llvm-symbolizer --exe /out/{self.harness_name} --output-style=JSON  | grep -vE \"(compiler-rt|covrec|include/c++|InstrProfilingValue.c|cxa_noexception.cpp)\" > {output_json}\n"

            output_on_the_host = str(
                self.artifacts_path) + f"{output_prefix}/{seed_name}.json"
            self.jsons.append(Path(output_on_the_host).resolve())
        return cmd

    def trace(self, *seeds):
        if self.__is_tracer_locked():
            raise Exception(
                f"This target folder [{self.project_path}] is already locked by a Tracer!\n You can manually remove the lock by deleting the file at {self.project_path}/artifacts/out/.covlib_tracer_locked")

        self.__lock_tracer()

        # CMD for tracing in the sanitizer-instrumented project
        self.get_functions()
        if self.trace_inlines:
            self.get_inlines()
        
        cmd = "export PIN_ROOT=/out/pin\nexport DR_BUILD=/out/dynamorio\nexport ASAN_OPTIONS=detect_leaks=0:symbolize=0:abort_on_error=1\n"
        
        self.jsons = []  # coverage results at these paths
        output_prefix = "/work"

        if self.use_rio:
            addendum = self.create_cmd_rio(seeds, output_prefix)
        else:
            addendum = self.create_cmd_pin(seeds, output_prefix)
        cmd += addendum
        
        command_file_host = self.create_cmd_file(
            cmd=cmd, base_path=self.project_path)
        command_file_name = os.path.basename(command_file_host)

        try:
            command_in_docker = f"/work/{command_file_name}"
            start = time.time()
            cmd_res = self.oss_fuzz_project.runner_image_run(
                command_in_docker, volumes={}, print_output=self.debug_mode)
            end = time.time()
            
            print("DEBUG: running tracer command in the docker container took ", (end-start), " seconds")
            if not self.debug_mode:
                command_file_host.unlink()
            
            if cmd_res.run_exit_code and cmd_res.run_exit_code != 0:
                print("[WARNING] Coverage collection failed at some point, checking")
            res = {}
            for s in self.jsons:
                # check on size of s
                if not s.exists() or s.stat().st_size < 20: # arbitrary size, we just want to avoid empty files
                    print(f"[WARNING] The file {s} does not exist or is empty, returning empty coverage")
                    res[s.stem] = [] ## REMINDER: on some seed, coverage might be empty
                else:
                    funcs = self.parser.parse_values(
                        oss_fuzz_project=None, coverage_path=s)
                    res[s.stem] = funcs
                
            assert self.__is_tracer_locked(), "The tracer was not locked, this is a bug ping @ubersandro"
            self.__unlock_tracer()    
            self.succeeded = True
            return res

            
        
        except Exception as e:
            print(e)
            print("[ERROR] The command failed to run in the container, this is a bug, ping @ubersandro")
            self.__unlock_tracer()

            return {}
