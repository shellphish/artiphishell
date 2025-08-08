#!/usr/bin/env python3 -u

import argparse
import logging
import multiprocessing as mp
import os
import psutil
import subprocess
import tempfile
import time

from pathlib import Path
from typing import List
from dataclasses import dataclass

import yaml
import hashlib
from shellphish_crs_utils.utils import artiphishell_should_fail_on_error
from shellphish_crs_utils.pydatatask.repos import PDTRepo
from shellphish_crs_utils.models.target import HarnessInfo
from shellphish_crs_utils.models.oss_fuzz import AugmentedProjectMetadata, LanguageEnum
from shellphish_crs_utils.models.coverage import FileCoverageMap
from shellphish_crs_utils.function_resolver import (
    RemoteFunctionResolver,
    LocalFunctionResolver,
)
from crs_telemetry.utils import init_otel, get_otel_tracer
from neomodel import db

from coveragelib import Tracer
from coveragelib.errors import BuddyTracerDiedException
from coveragelib.parsers.line_coverage import (
    C_LineCoverageParser_LLVMCovHTML,
    Java_LineCoverageParser_Jacoco,
)
from analysis_graph.api.dynamic_coverage import register_harness_input_file_coverage
from permanence.client import PermanenceClient

from pympler import asizeof


init_otel("coverage-guy", "dynamic_analysis", "input-tracing")
telemetry_tracer = get_otel_tracer()

LOGGING_FORMAT = "%(levelname)s | %(name)s | %(message)s"
logging.basicConfig(level=logging.INFO, format=LOGGING_FORMAT)
logger = logging.getLogger("coverageguy")
logger.setLevel(logging.INFO)

class AnalysisGraphAPI:
    
    def __init__(self):
        pass

    @staticmethod
    def run_cypher_query(query: str, resolve_objects: bool):
        attempts = 3
        for attempt in range(1, attempts + 1):
            try:
                results, columns = db.cypher_query(query=query, resolve_objects=resolve_objects)
                return results, columns
            except Exception as e:
                if attempt < attempts:
                    logger.warning(f"❓ Error: {e}, retrying... (Attempt {attempt}/{attempts})")
                    time.sleep(60)  # Wait for a minute before retrying
                else:
                    logger.error(f"❌ Error: {e}, failed after {attempts} attempts.")
                    return None, None
        return None, None

    def get_all_covered_inputs(self):
        query = """
        MATCH (input:HarnessInputNode)-[:COVERS]->(f:CFGFunction)
        RETURN input.content_hex
        """
        all_md5_hashes = []
        results, columns = self.run_cypher_query(query=query, resolve_objects=True)
        
        try:
            results = results[0]
        except IndexError:
            logger.warning(" 🏜️ No results found for the query. Returning empty list.")
            return all_md5_hashes
        
        for x in results:
            data_bytes = bytes.fromhex(x)
            seed_md5 = hashlib.md5(data_bytes).hexdigest()
            all_md5_hashes.append(seed_md5)

        return all_md5_hashes

class Config:
    def __init__(self, language: LanguageEnum):
        self.is_local_run: bool = os.getenv("LOCAL_RUN", "False").lower() in ["1", "true", "t", "yes", "y"]
        self.verbose_covguy: bool = False
        self.with_permanence: bool = False
        self.recover_tracer_crashes: bool = False
        self.max_batch_size: int = 10
        self.num_db_uploaders: int = 4 if not self.is_local_run else 0
        self.num_coverage_processors: int = 4
        self.max_upload_queue_size: int = 100
        self.parser: dict = {
            LanguageEnum.c: C_LineCoverageParser_LLVMCovHTML,
            LanguageEnum.cpp: C_LineCoverageParser_LLVMCovHTML,
            LanguageEnum.jvm: Java_LineCoverageParser_Jacoco,
        }[language]()
        self.timeout: dict = {
            LanguageEnum.c: 20,
            LanguageEnum.cpp: 20,
            LanguageEnum.jvm: 60,
        }[language]


@dataclass
class SharedState:
    manager: mp.Manager
    project_id: str
    project_name: str
    project_language: LanguageEnum
    harness_info: HarnessInfo
    harness_id: str
    harness_name: str
    function_index: Path
    function_index_json_dir: Path
    config: Config
    benign_inputs_dir: Path
    benign_inputs_dir_lock: Path
    crashing_inputs_dir: Path
    crashing_inputs_dir_lock: Path

    def __post_init__(self):
        self.seen_files = self.manager.dict()
        self.seen_functions = self.manager.dict()
        self.seeds_already_traced = self.manager.dict()
        self.upload_queue = self.manager.Queue()
        self.lock = self.manager.Lock()
        self.stop_event = self.manager.Event()


@dataclass
class UploadJob:
    seed_path: str
    is_crashing: bool
    coverage_map: FileCoverageMap
    new_functions_hit: List[str] = None
    new_file_hit: List[str] = None


def create_function_resolver(
    config: Config,
    project_name: str,
    project_id: str,
    function_index: Path,
    function_index_json_dir: Path
):
    if config.is_local_run:
        return LocalFunctionResolver(function_index, function_index_json_dir)
    else:
        return RemoteFunctionResolver(project_name, project_id)


class DBUploader:
    """
    This class is responsible for uploading the seeds to the analysis graph.
    """

    def __init__(
        self,
        uploader_id: int,
        shared_state: SharedState
    ):

        self.uploader_id = uploader_id
        self.shared_state = shared_state

    def start(self):
        logger.info(f"[DBUploader {self.uploader_id}] Starting DBUploader process...")

        function_resolver = create_function_resolver(
            self.shared_state.config,
            self.shared_state.project_name,
            self.shared_state.project_id,
            self.shared_state.function_index,
            self.shared_state.function_index_json_dir,
        )

        if self.shared_state.config.with_permanence:
            permanence_client = PermanenceClient(function_resolver)
        else:
            permanence_client = None

        while not self.shared_state.stop_event.is_set():
            time.sleep(1)
            try:
                # Non-blocking get with timeout
                try:
                    upload_job = self.shared_state.upload_queue.get(timeout=1)
                except:
                    continue

                seed_kind = "crashing" if upload_job.is_crashing else "benign"
                logger.info(f'[DBUploader {self.uploader_id}] Registering {seed_kind} seed in the analysis graph: {upload_job.seed_path}')

                try:
                    # Read seed bytes just before upload
                    with open(upload_job.seed_path, "rb") as f:
                        seed_bytes = f.read()
                    
                    start_time = time.time()
                    register_harness_input_file_coverage(
                        Path(upload_job.seed_path).name,
                        self.shared_state.harness_id,
                        self.shared_state.harness_info,
                        seed_bytes,
                        upload_job.is_crashing,
                        function_resolver,
                        upload_job.coverage_map,
                    )
                    end_time = time.time()
                    logger.info(f"[DBUploader {self.uploader_id}] Upload time: {end_time - start_time}")

                    if self.shared_state.config.with_permanence:
                        permanence_client.seeds_reached(
                            project_name=self.shared_state.project_name,
                            harness_name=self.shared_state.harness_name,
                            seeds=[seed_bytes],
                            hit_functions=upload_job.new_functions_hit,
                            hit_files=upload_job.new_file_hit,
                        )

                except Exception as e:
                    logger.info(f"[DBUploader {self.uploader_id}] Error while uploading: {e}")
                    import traceback
                    traceback.print_exc()

                    if artiphishell_should_fail_on_error():
                        logger.info("[DBUploader] we are dying here because of artiphishell_should_fail_on_error")
                        # Signal to stop all processes
                        self.shared_state.stop_event.set()
                        raise e

            except Exception as e:
                logger.info(f"[DBUploader {self.uploader_id}] General error in uploader: {e}")
                import traceback
                traceback.print_exc()


class CovguyTracer:
    """Class responsible for tracing coverage information."""

    def __init__(
        self,
        tracer_id: int,
        target_dir: Path,
        shared_state: SharedState,
    ):
        # Sanity checks
        assert isinstance(tracer_id, int), "tracer_id must be an int"
        assert isinstance(target_dir, Path), "target_dir must be a Path"
        assert os.path.isdir(target_dir), f"Target directory {target_dir} is not a directory."

        self.tracer_id = tracer_id
        self.target_dir = target_dir
        self.shared_state = shared_state

        self.function_resolver = None

        # Instantiate the pdt repos
        self.benign_pdt_repo = PDTRepo(self.shared_state.benign_inputs_dir, self.shared_state.benign_inputs_dir_lock)
        self.crashing_pdt_repo = PDTRepo(self.shared_state.crashing_inputs_dir, self.shared_state.crashing_inputs_dir_lock)

    def start(self):
        logger.info(f"[CovguyTracer {self.tracer_id}] Starting CovguyTracer process ({self.target_dir=})...")

        # Instantiate a function resolver based on the environment
        self.function_resolver = create_function_resolver(
            self.shared_state.config,
            self.shared_state.project_name,
            self.shared_state.project_id,
            self.shared_state.function_index,
            self.shared_state.function_index_json_dir,
        )

        with telemetry_tracer.start_as_current_span(
            f"coverage-guy-tracer-{self.tracer_id}.trace"
        ):
            # Create a tracer instance along with monitor objects
            with Tracer(
                self.target_dir,
                self.shared_state.harness_name,
                parser=self.shared_state.config.parser,
                aggregate=False,
                timeout_per_seed=self.shared_state.config.timeout
            ) as cov_tracer:
                while not self.shared_state.stop_event.is_set():
                    time.sleep(1)
    
                    # Check queue size before processing more seeds
                    queue_size = self.shared_state.upload_queue.qsize()
                    if queue_size > self.shared_state.config.max_upload_queue_size:
                        logger.warning(f"[DIAGNOSTIC] Upload queue too large ({queue_size}), sleeping to prevent OOM")
                        time.sleep(30)
                        continue
                    
                    with telemetry_tracer.start_as_current_span(f"coverage-guy-tracer-{self.tracer_id}.trace.round"):
                        self.print_stats()

                        try:
                            # Fetch and process seeds from both queues
                            self.fetch_from_repo(
                                self.benign_pdt_repo,
                                cov_tracer,
                                self.shared_state
                            )

                            self.fetch_from_repo(
                                self.crashing_pdt_repo,
                                cov_tracer,
                                self.shared_state
                            )

                        except BuddyTracerDiedException:
                            logger.critical("The buddy tracer died on fire...")
                            # Signal to stop all processes
                            self.shared_state.stop_event.set()
                            assert False
                        except Exception as e:
                            logger.error(f"Error while tracing: {e}")
                            import traceback

                            traceback.print_exc()
                            if artiphishell_should_fail_on_error():
                                # Signal to stop all processes
                                self.shared_state.stop_event.set()
                                raise e
                            continue

    def print_stats(self):
        """Print diagnostic information about the system state."""
        pid = os.getpid()  # Get current process ID
        process = psutil.Process(pid)
        memory = process.memory_info().rss / (1024 * 1024)  # Convert to MB
        cpu = process.cpu_percent(interval=1)  # CPU usage over 1 second
        logger.info(f"======tracer-{self.tracer_id}======")
        logger.info(f"[DIAGNOSTIC] Memory Usage: {memory:.2f} MB | CPU Usage: {cpu:.2f}%")
        logger.info(f"[DIAGNOSTIC] Size of the function resolver is: {asizeof.asizeof(self.function_resolver)}")
        logger.info(f"[DIAGNOSTIC] Size of the SEEDS_ALREADY_TRACED is: {len(self.shared_state.seeds_already_traced)}")
        logger.info(f"[DIAGNOSTIC] Size of the SEEDS_TO_UPLOAD is: {self.shared_state.upload_queue.qsize()}")
        logger.info(f"==============================")

    def fetch_from_repo(
        self,
        pdt_repo: PDTRepo,
        tracer: Tracer,
        shared_state: SharedState,
    ):
        """Process items from the queue and add them to upload queue."""
        logger.info(f"[DIAGNOSTIC] Fetching from queue {pdt_repo.main_dir}...")

        is_crashing = True if "crashing_harness" in str(pdt_repo.main_dir) else False

        curr_workdir = list()
        ready_seed_names = set(os.listdir(pdt_repo.main_dir)) - set(os.listdir(pdt_repo.lock_dir))
        logger.info(f"[DIAGNOSTIC] Found {len(ready_seed_names)} ready seeds in {pdt_repo.main_dir}")
        for seed_name in ready_seed_names:
            if len(curr_workdir) >= shared_state.config.max_batch_size:
                break  # Stop if we reached the max batch size

            with shared_state.lock:
                if seed_name in shared_state.seeds_already_traced:
                    continue  # Skip seeds that were already traced
                shared_state.seeds_already_traced[seed_name] = True

            seed_path = pdt_repo.get_content_paths(seed_name)["main_repo"]
            
            curr_workdir.append(seed_path)
            logger.info(f"New seed to trace from {pdt_repo.main_dir}: {seed_path}")

        if len(curr_workdir) > 0:
            file_coverage_maps: List[FileCoverageMap] = tracer.trace(*curr_workdir)
            all_covered_files = set()
            for coverage_map in file_coverage_maps:
                # The keys are the file covered by that seed
                all_covered_files = all_covered_files.union(set(coverage_map.keys()))

            # The new hit files are the ones that are not appearing yet in the seen_files
            new_hit_files = all_covered_files.difference(set(shared_state.seen_files.keys()))

            # Update the seen_files with the new files
            shared_state.seen_files.update({f: True for f in new_hit_files})

            for seed, coverage_map in zip(curr_workdir, file_coverage_maps):

                per_seed_new_hit_funcs = set()
                if shared_state.config.verbose_covguy:
                    # THIS IS SLOW, WE PROBABLY DON'T WANT IT DURING THE GAME.
                    for new_hit_file in new_hit_files:
                        logger.info(f"[DIAGNOSTIC-REMOVE-ME-LATER] New file seen: {new_hit_file}")
                    function_coverage = self.function_resolver.get_function_coverage(coverage_map)
                    for function_key, lines in function_coverage.items():
                        for l in lines:
                            if l.count_covered and l.count_covered > 0:
                                if function_key not in shared_state.seen_functions:
                                    shared_state.seen_functions[function_key] = True
                                    per_seed_new_hit_funcs.add(function_key)
                                    logger.info(f"[DIAGNOSTIC-REMOVE-ME-LATER] New function seen: {function_key}")
                                    break  # go to next function_key

                # Add to upload queue
                upload_job = UploadJob(
                    seed_path=seed,
                    is_crashing=is_crashing,
                    coverage_map=coverage_map,
                    new_functions_hit=list(per_seed_new_hit_funcs),
                    new_file_hit=list(new_hit_files),
                )
                self.shared_state.upload_queue.put(upload_job)
        else:
            logger.info(f"[DIAGNOSTIC] The curr_workdir for {pdt_repo.main_dir} was empty...")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--harness_info_id", required=True)
    parser.add_argument("--harness_info", required=True)
    parser.add_argument("--target_dir", required=True)
    parser.add_argument("--project_metadata", required=True)
    parser.add_argument("--project_id", required=True)
    parser.add_argument("--function_index", required=True)
    parser.add_argument("--function_index_json_dir", required=True)
    parser.add_argument("--crashing_inputs_dir", required=True)
    parser.add_argument("--crashing_inputs_dir_lock", required=True)
    parser.add_argument("--benign_inputs_dir", required=True)
    parser.add_argument("--benign_inputs_dir_lock", required=True)

    args = parser.parse_args()

    # Last second addition, I prefer to have a simple object here.
    md5_of_all_seeds_with_coverage = []
    try:
        analysis_graph_api = AnalysisGraphAPI()
        md5_of_all_seeds_with_coverage = analysis_graph_api.get_all_covered_inputs()
    except Exception as e:
        logger.error(f" 🤯 Error while fetching all covered inputs: {e}. Proceeding with empty...")

    logger.info(f'👀 There are {len(md5_of_all_seeds_with_coverage)} seeds already covered in the analysis graph.')

    with telemetry_tracer.start_as_current_span("coverage-guy.main"):

        # Load project configuration
        with open(args.harness_info, "r") as f:
            harness_info = HarnessInfo.model_validate(yaml.safe_load(f))

        with open(args.project_metadata, "r") as f:
            project_metadata = AugmentedProjectMetadata.model_validate(yaml.safe_load(f))

        logger.info(f"======================================================")
        logger.info(f"PDTRepoMonitoring:")
        logger.info(f"- pydatatask benign inputs dir: {args.benign_inputs_dir}")
        logger.info(f"- pydatatask crashing inputs dir: {args.crashing_inputs_dir}")
        logger.info(f"======================================================")

        # Create a manager for handling shared data structures
        manager = mp.Manager()
        shared_state = SharedState(
            manager=manager,
            project_id=args.project_id,
            project_name=project_metadata.shellphish_project_name,
            project_language=project_metadata.language,
            harness_info=harness_info,
            harness_id=args.harness_info_id,
            harness_name=harness_info.cp_harness_name,
            function_index=Path(args.function_index),
            function_index_json_dir=Path(args.function_index_json_dir),
            config=Config(project_metadata.language),
            benign_inputs_dir=Path(args.benign_inputs_dir),
            benign_inputs_dir_lock=Path(args.benign_inputs_dir_lock),
            crashing_inputs_dir=Path(args.crashing_inputs_dir),
            crashing_inputs_dir_lock=Path(args.crashing_inputs_dir_lock),
        )

        # Preload the md5s of all seeds that already have coverage
        logger.info(f"Preloading seeds that already have coverage...")
        for md5_hash in md5_of_all_seeds_with_coverage:
            shared_state.seeds_already_traced[md5_hash] = True
        logger.info(f"✅ Shared state initialized with {len(shared_state.seeds_already_traced)} preloaded seeds.")

        ####################################
        # ⏫
        ####################################
        # Start uploader processes
        ####################################
        ####################################
        uploader_processes = []
        logger.info(f"Starting {shared_state.config.num_db_uploaders} DBUploaders as separate processes...")
        for uploader_id in range(shared_state.config.num_db_uploaders):
            uploader = DBUploader(
                uploader_id,
                shared_state
            )

            p = mp.Process(target=uploader.start)
            p.daemon = True
            p.start()
            uploader_processes.append(p)

        ####################################
        # ⏫
        ####################################
        # Start coverage processes
        ####################################
        ####################################
        tracer_processes = []
        logger.info(f"Starting {shared_state.config.num_coverage_processors} CovguyTracers as separate processes...")
        for covguy_id in range(shared_state.config.num_coverage_processors):
            # Create a separate copy of the target directory for each tracer
            new_target_dir = Path(
                tempfile.mkdtemp(prefix=f"covguy_tracer_{covguy_id}_", dir="/shared/coverageguy")
            )
            try:
                subprocess.run(
                    ["rsync", "-a", "--ignore-missing-args", args.target_dir+"/", new_target_dir],
                    check=True, capture_output=True, text=True,
                )
                logger.info(f"Created folder at {new_target_dir} for tracer {covguy_id}")
            except subprocess.CalledProcessError as e:
                logger.error(f"Error during rsync: {e.stderr}")
                raise

            logger.info(f"Created a new folder at {new_target_dir} for tracer {covguy_id}")

            # Create and start the tracer process
            covguy_tracer = CovguyTracer(
                covguy_id,
                new_target_dir,
                shared_state
            )

            p = mp.Process(target=covguy_tracer.start)
            p.daemon = True
            p.start()
            tracer_processes.append(p)

        try:
            # Wait for processes to complete (they run indefinitely until error or external termination)
            for p in tracer_processes + uploader_processes:
                p.join()

        except Exception as e:
            logger.critical(f"THE COVERAGEGUY MONITOR DIED: {e}")

            import traceback
            traceback.print_exc()

            # Signal to stop all processes
            shared_state.stop_event.set()

            # Give processes time to clean up
            time.sleep(2)

            # Terminate any remaining processes
            for p in tracer_processes + uploader_processes:
                if p.is_alive():
                    p.terminate()
