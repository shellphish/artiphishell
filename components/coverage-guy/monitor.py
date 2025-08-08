#!/usr/bin/env python3 -u

import argparse
import logging
import os
import fcntl
import time
import yaml
import shutil
import threading
import psutil

from queue import Queue
from typing import List
from pathlib import Path

from shellphish_crs_utils.utils import artiphishell_should_fail_on_error
from shellphish_crs_utils.pydatatask.repos import PDTRepo, PDTRepoMonitor
from shellphish_crs_utils.models.target import HarnessInfo
from shellphish_crs_utils.models.oss_fuzz import AugmentedProjectMetadata, LanguageEnum
from shellphish_crs_utils.models.coverage import FileCoverageMap
from shellphish_crs_utils.function_resolver import RemoteFunctionResolver, LocalFunctionResolver
from crs_telemetry.utils import init_otel, get_otel_tracer

from coveragelib import Tracer
from coveragelib.errors import BuddyTracerDiedException
from coveragelib.parsers.line_coverage import C_LineCoverageParser_LLVMCovHTML, Java_LineCoverageParser_Jacoco

from analysis_graph.api.dynamic_coverage import register_harness_input_file_coverage

from permanence.client import PermanenceClient

# DIAGNOSTIC 
from pympler import asizeof

init_otel("coverage-guy", "dynamic_analysis", "input-tracing")
telemetry_tracer = get_otel_tracer()
LOGGING_FORMAT = "%(levelname)s | %(name)s | %(message)s"
logging.basicConfig(level=logging.INFO, format=LOGGING_FORMAT)

logger = logging.getLogger("coverageguy")
logger.setLevel(logging.INFO)

LANGUAGE_TO_PARSER = {
    LanguageEnum.c: C_LineCoverageParser_LLVMCovHTML,
    LanguageEnum.cpp: C_LineCoverageParser_LLVMCovHTML,
    LanguageEnum.jvm: Java_LineCoverageParser_Jacoco,
}

# Storing the seeds that were already traced in memory
# (we never seen more than 10,000 seeds, so even if this is 10X we are good)
SEEDS_ALREADY_TRACED = set()

# This queue is shared between the main thread and the DBUploader threads.
SEEDS_TO_UPLOAD = Queue()

# This is a set of seen functions that have been covered so far!
VERBOSE_COVGUY = False
# TODO: If this is True, we attempt to restart the Tracer if we catch a BuddyTracerDiedException.
RECOVER_TRACER_CRASHES = False

# Weather we want to push the seeds in libpermanence
WITH_PERMANENCE = False

SEEN_FILES = set()
SEEN_FUNCTIONS = set()

def was_file_traced(seed_name: str) -> bool:

    # Half the seed name (these are hashes) we can safely use half of it and still
    # avoid collisions.
    #seed_name = seed_name[:len(seed_name)//2]

    if seed_name in SEEDS_ALREADY_TRACED:
        return True
    else:
        SEEDS_ALREADY_TRACED.add(seed_name)
        return False
    

class DBUploader:
    '''
    This class is responsible for uploading the seeds to the analysis graph.
    '''
    def __init__(self, uploader_id, project_name, harness_name, function_resolver, is_permanence_on=False):
        self.project_name = project_name
        self.harness_name = harness_name
        self.uploader_id = uploader_id
        self.function_resolver = function_resolver
        self.is_permanence_on = is_permanence_on
        if self.is_permanence_on:
            self.permanence_client = PermanenceClient(
                function_resolver=self.function_resolver
            )
        else:
            self.permanence_client = None




    def start(self):
        while True:
            if SEEDS_TO_UPLOAD.qsize() > 0:
                # Get the next seed to upload (this Queue is filled up by the fetch_from_queue)
                upload_job = SEEDS_TO_UPLOAD.get()
                seed_kind = "crashing" if "crashing" in str(upload_job.seed) else "benign"
                logger.info(f'[DBUploader {self.uploader_id}] Registering {seed_kind} seed in the analysis graph: {upload_job.seed}')
                try:
                    start_time = time.time()
                    #logger.info("[DIAGNOSTIC] The number of keys ")
                    #function_coverage = function_resolver.get_function_coverage(upload_job.fcm)
                    register_harness_input_file_coverage(
                                                         Path(upload_job.seed).name,
                                                         upload_job.harness_id, 
                                                         upload_job.harness_info, 
                                                         upload_job.seed_bytes, 
                                                         upload_job.is_crashing, 
                                                         upload_job.function_resolver,
                                                         upload_job.fcm
                                                         )
                    end_time = time.time()
                    logger.info(f'[DBUploader {self.uploader_id}] Upload time: {end_time - start_time}')
                    
                    if self.is_permanence_on and (upload_job.new_functions_hit or upload_job.new_file_hit):
                        self.permanence_client.seeds_reached(
                                project_name=self.project_name,
                                harness_name=self.harness_name,
                                seeds=[upload_job.seed_bytes],
                                hit_functions=upload_job.new_functions_hit,
                                hit_files=upload_job.new_file_hit,
                            )

                except Exception as e:
                    logger.info(f'[DBUploader {self.uploader_id}] Error while uploading: {e}')
                    import traceback
                    traceback.print_exc()
                    if artiphishell_should_fail_on_error():
                        logger.info(f'[DBUploader] we are dying here because of artiphishell_should_fail_on_error')
                        # If we are running in CI we are just dying here.
                        raise e
            else:
                time.sleep(0.5)


class UploadJob:
    def __init__(self, seed, harness_id, harness_info, seed_bytes, is_crashing, function_resolver, fcm, new_functions_hit=None, new_file_hit=None):
        self.seed = seed
        self.harness_id = harness_id
        self.harness_info = harness_info
        self.seed_bytes = seed_bytes
        self.is_crashing = is_crashing
        self.function_resolver = function_resolver
        self.fcm = fcm
        self.new_functions_hit = new_functions_hit
        self.new_file_hit = new_file_hit



def fetch_from_queue(pdt_queue: Queue, pdt_repo: PDTRepo, tracer: Tracer, function_resolver: RemoteFunctionResolver):
    
    global SEEDS_TO_UPLOAD
    global SEEN_FUNCTIONS
    global SEEN_FILES

    curr_workdir = list()

    logger.info(f'[DIAGNOSTIC] Fetching from queue {pdt_repo.main_dir}...')
    is_crashing_seed = True if "crashing_harness" in str(pdt_repo.main_dir) else False
    curr_queue_size = pdt_queue.qsize()
    logger.info(f'[DIAGNOSTIC]  - Queue size: {curr_queue_size}')
    
    # For safety, keep the batch to 1. Otherwise if the stream of incoming seed is slow,
    # we might end up lagging behind just because we are waiting for more seeds to come.
    while pdt_queue.qsize() > 0 and len(curr_workdir) < 1:
        new_seed_to_trace_key = pdt_queue.get()
        new_seed_path = pdt_repo.get_content_paths(new_seed_to_trace_key)['main_repo']

        logger.info(f'New seed to trace from {pdt_repo.main_dir}: {new_seed_path}')

        seed_name = os.path.basename(new_seed_path)

        if not was_file_traced(seed_name):
            curr_workdir.append(new_seed_path)
    
    if len(curr_workdir) != 0:
        file_coverage_maps:List[FileCoverageMap] = tracer.trace(*curr_workdir)
        all_covered_files = set()
        for fcm in file_coverage_maps:
            # The keys of an fcm are the file covered by that seed
            all_covered_files = all_covered_files.union(set(fcm.keys()))
        
        # The new hit files are the one that are not appearing yet in the SEEN_FILES
        new_hit_files = all_covered_files.difference(SEEN_FILES)
        # Update the SEEN_FILES with the new files
        SEEN_FILES.update(new_hit_files)
        
        for seed, fcm in zip(curr_workdir, file_coverage_maps):
            with open(seed, "rb") as f:
                seed_bytes = f.read()

            if VERBOSE_COVGUY:
                for new_hit_file in new_hit_files:
                    print(f'- [DIAGNOSTIC-REMOVE-ME-LATER] New file seen: {new_hit_file}')

                per_seed_new_hit_funcs = set()
                # THIS IS SLOW, WE PROBABLY DON'T WANT IT DURING THE GAME.
                function_coverage = function_resolver.get_function_coverage(fcm)
                for function_key, lines in function_coverage.items():
                    for l in lines:
                        if l.count_covered and l.count_covered > 0:
                            if function_key not in SEEN_FUNCTIONS:
                                SEEN_FUNCTIONS.add(function_key)
                                per_seed_new_hit_funcs.add(function_key)
                                logger.info(f'-  [DIAGNOSTIC-REMOVE-ME-LATER] New function seen: {function_key}')
                                break # go to next function_key

            # Register it in the SEEDS_TO_UPLOAD queue, the DBUploader will take care of it.
            if not WITH_PERMANENCE:
                SEEDS_TO_UPLOAD.put(
                                    UploadJob(
                                            seed,
                                            args.harness_info_id, 
                                            harness_info, 
                                            seed_bytes, 
                                            is_crashing_seed,
                                            function_resolver, 
                                            fcm
                                            )
                                    )
            else:
                print("[DEBUG] Registering the seed with libpermanence!")
                SEEDS_TO_UPLOAD.put(
                                    UploadJob(
                                            seed,
                                            args.harness_info_id, 
                                            harness_info, 
                                            seed_bytes, 
                                            is_crashing_seed,
                                            function_resolver, 
                                            fcm,
                                            new_functions_hit=list(per_seed_new_hit_funcs),
                                            new_file_hit=list(new_hit_files)
                                            )
                                    )
    else:
        # If there was nothing to do, we can wait a few seconds before checking again.
        logger.info(f"[DIAGNOSTIC] The curr_workdir for {pdt_repo.main_dir} was empty...")

def __print_stats(function_resolver):
    global SEEDS_TO_UPLOAD
    pid = os.getpid()  # Get current process ID
    process = psutil.Process(pid)
    memory = process.memory_info().rss / (1024 * 1024)  # Convert to MB
    cpu = process.cpu_percent(interval=1)  # CPU usage over 1 second
    logger.info(f"[DIAGNOSTIC] Memory Usage: {memory:.2f} MB | CPU Usage: {cpu:.2f}%")    
    logger.info(f" [DIAGNOSTIC] Size of the function resolver is: {asizeof.asizeof(function_resolver)}")
    logger.info(f" [DIAGNOSTIC] Size of the SEEDS_ALREADY_TRACED is: {len(SEEDS_ALREADY_TRACED)}")
    logger.info(f" [DIAGNOSTIC] Size of the SEEDS_TO_UPLOAD is: {SEEDS_TO_UPLOAD.qsize()}")


# DISCUSSION:
#  - We decided to use only one thread per coverage guy instance so we can 
#    easily scale the amount of instances depending on the load of seeds we need to 
#    trace.
#  - Every new instance of coverage guy will received all the seeds that are currently 
#    in the PDT folder. To check if a seed was already traced, we are doing a lookup in 
#    the analysis graph and see if a seeds has a "coverage-start" entry, or has "coverage-results".
#    if yes, we skip.
#  - To check if a seed is ready to be traced (fully written by PDT) we are leveraging the PDTRepoMonitor
#    that basically wait for a lock file to disappeard before the file being available in the PDTRepo.
if __name__ == "__main__":
    argparse = argparse.ArgumentParser()
    argparse.add_argument("--harness_info_id", required=True)
    argparse.add_argument("--harness_info", required=True)
    argparse.add_argument("--target_dir", required=True)
    argparse.add_argument("--project_metadata", required=True)
    argparse.add_argument("--project_id", required=True)
    argparse.add_argument("--function_index", required=True)
    argparse.add_argument("--function_index_json_dir", required=True)
    
    argparse.add_argument("--crashing_inputs_dir", required=True)
    argparse.add_argument("--crashing_inputs_dir_lock", required=True)
    
    argparse.add_argument("--benign_inputs_dir", required=True)
    argparse.add_argument("--benign_inputs_dir_lock", required=True)

    args = argparse.parse_args()

    with telemetry_tracer.start_as_current_span("coverage-guy.main"):
        original_benign_inputs_dir = args.benign_inputs_dir

        # Load the harness info yaml
        with open(args.harness_info, "r") as f:
            harness_info = HarnessInfo.model_validate(yaml.safe_load(f))
        with open(args.project_metadata, "r") as f:
            project_metadata = AugmentedProjectMetadata.model_validate(yaml.safe_load(f))

        harness_name = harness_info.cp_harness_name
        language = project_metadata.language
        
        active_parser =  LANGUAGE_TO_PARSER[language]
        active_parser = active_parser()

        benign_inputs_pdt_dir = PDTRepo(args.benign_inputs_dir, args.benign_inputs_dir_lock)
        crashing_inputs_pdt_dir = PDTRepo(args.crashing_inputs_dir, args.crashing_inputs_dir_lock)

        # This is the queue we are watching for new seeds
        # The PDTRepoMonitor will take care of filling up this queue.
        benign_workdir_queue = Queue()
        crashing_workdir_queue = Queue()

        benign_pdt_monitor   = PDTRepoMonitor(benign_inputs_pdt_dir, benign_workdir_queue)
        crashing_pdt_monitor = PDTRepoMonitor(crashing_inputs_pdt_dir, crashing_workdir_queue)

        logger.info(f'======================================================')
        logger.info(f' PDTRepoMonitoring:')
        logger.info(f'  - pydatatask benign inputs dir: {benign_inputs_pdt_dir}')
        logger.info(f'  - pydatatask crashing inputs dir: {crashing_inputs_pdt_dir}')
        logger.info(f'======================================================')

        function_index = Path(args.function_index)
        function_index_json_dir = Path(args.function_index_json_dir)
        if os.getenv('LOCAL_RUN') == 'False':
            function_resolver = RemoteFunctionResolver(project_metadata.shellphish_project_name, args.project_id)
        else:
            function_resolver = LocalFunctionResolver(function_index, function_index_json_dir)

        # Start the DBUploader thread
        DB_UPLOADERS = list()
        NUM_UPLOADERS = 4

        logger.info(f'Starting {NUM_UPLOADERS} DBUploaders...')
        for i in range(NUM_UPLOADERS):
            uploader = DBUploader(i, project_metadata.shellphish_project_name, harness_name, function_resolver, WITH_PERMANENCE)
            t = threading.Thread(target=uploader.start)
            t.start()
            DB_UPLOADERS.append(t)

        logger.info(f'Starting coverage guy monitor for {harness_name}...')

        if language == LanguageEnum.c or language == LanguageEnum.cpp:
            timeout = 20
        else:
            timeout = 60

        with telemetry_tracer.start_as_current_span("coverage-guy.trace"):
            # NOTE: remember, this is spawning a long-running container that does the tracing.
            with Tracer(args.target_dir, harness_name, parser=active_parser, aggregate=False, timeout_per_seed=timeout) as cov_tracer, benign_pdt_monitor, crashing_pdt_monitor:
                while True:
                    with telemetry_tracer.start_as_current_span("coverage-guy.trace.round"):
                        __print_stats(function_resolver)
                        # This forces the PDTMonitor to add stuff to the Queue.
                        benign_pdt_monitor.external_update()
                        crashing_pdt_monitor.external_update()
                        
                        try:
                            # Fetch new seeds from the benign queue and trace them
                            fetch_from_queue(benign_workdir_queue, benign_inputs_pdt_dir, cov_tracer, function_resolver)
                            # Fetch new seeds from the crashing queue and trace them
                            fetch_from_queue(crashing_workdir_queue, crashing_inputs_pdt_dir, cov_tracer, function_resolver)
                        except BuddyTracerDiedException as e:
                            logger.info("[CRITICAL] The buddy tracer died on fire...")
                            # TODO: recover from this maybe by instantiating a new tracer?
                            assert False
                        except Exception as e:
                            logger.info(f'Error while tracing: {e}')
                            import traceback
                            traceback.print_exc()
                            if artiphishell_should_fail_on_error():
                                # If we are running in CI we are just dying here.
                                raise e
                            continue
