import agentlib
import argparse
import yaml
import logging
import os
import shutil 
import random

from discoveryguy.config import Config, DiscoverGuyMode, CRSMode


from crs_telemetry.utils import (
    init_otel,
    get_otel_tracer,
    init_llm_otel,
    status_ok,
)

init_otel("discoveryguy", "static_analysis", "llm_bug_discovery")
init_llm_otel()

logger = logging.getLogger("discoveryguy")
logger.setLevel(logging.INFO)
otel_tracer = get_otel_tracer()


import os
import time
import tempfile
import subprocess
import requests
from shellphish_crs_utils.pydatatask.client import PDClient
from pathlib import Path
import multiprocessing
from typing import List
import logging
from shellphish_crs_utils.models.oss_fuzz import AugmentedProjectMetadata


logger = logging.getLogger(__name__)

def init_worker_logging():
    """Initialize logging for multiprocessing worker processes"""
    # Configure logging for the worker process
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - PID:%(process)d - %(message)s',
        force=True  # This ensures the configuration is applied even if logging was already configured
    )


# 🪄 Amy's magic.
class DebugArtifactDownloader():

    def __init__(self, project_name, oss_fuzz_debug_targets_folder, oss_fuzz_repo_path):
        self.extracted_tars = {}
        self.project_name = project_name

        # This is the top directory that will contain all debug artifacts
        # The variable oss_fuzz_debug_targets_folder points to /shared/discoveryguy/tmp.12345/
        # e.g.,
        #                                
        # /shared/discoveryguy/tmp.12345/<build_X>/projects/<project_name>/
        # /shared/discoveryguy/tmp.12345/<build_Y>/projects/<project_name>/
        # /shared/discoveryguy/tmp.12345/<build_Z>/projects/<project_name>/
        # -------------------------------
        #               |
        #               V
        # Sent by the previous bash script
        self.oss_fuzz_debug_targets_folder = oss_fuzz_debug_targets_folder

        # This is an oss-fuzz repo path like /shared/discoveryguy/tmp.7844/
        #                                                                  |-> projects
        #                                                                  |-> infra
        #                                                                  |-> ... 
        #  
        # The variable oss_fuzz_repo_path points to /shared/discoveryguy/tmp.7844/
        self.oss_fuzz_repo_path = oss_fuzz_repo_path

        # Create a temporary directory to store all the debug artifacts and extract them later
        self.all_debug_builds_artifacts_dir = tempfile.mkdtemp(prefix="all_debug_builds_")

    def get_pd_client(self):
        if PDClient is None:
            logger.error("PDClient is not installed")
            raise ValueError("PDClient is not installed")

        CRS_TASK_NUM = os.environ.get("CRS_TASK_NUM", os.environ.get("ARTIPHISHELL_GLOBAL_ENV_CRS_TASK_NUM", None))

        agent_url = os.environ.get(f"PYDATATASK_AGENT_{CRS_TASK_NUM}_PORT",
            os.environ.get("PYDATATASK_AGENT_PORT",
            os.environ.get("PDT_AGENT_URL", "")
        ))
        agent_url = agent_url.replace("tcp://", "http://")
        agent_secret = os.environ.get("AGENT_SECRET", os.environ.get("PDT_AGENT_SECRET", ""))

        if not agent_url:
            logger.error(f"PD agent URL is not set in environment variables for CRS_TASK_NUM={CRS_TASK_NUM}")
            raise ValueError(f"PD agent URL is not set in environment variables for CRS_TASK_NUM={CRS_TASK_NUM}")

        return PDClient(agent_url, agent_secret)


    def try_to_download_debug_artifact(self, build_id: str):
        worker_logger = logging.getLogger(__name__)
        worker_logger.info(f"Starting download attempt for build {build_id}")
        
        try:
            output_tar = tempfile.NamedTemporaryFile(delete=False)
            worker_logger.info(f"Created temporary file: {output_tar.name} for build {build_id}")
        except Exception as e:
            worker_logger.error(f"Failed to create temporary file for build {build_id}: {e}")
            return None
        
        try:
            client = self.get_pd_client()
            worker_logger.info(f"PDClient initialized for build {build_id}")
        except Exception as e:
            worker_logger.error(f"Failed to get PDClient for build {build_id}: {e}")
            output_tar.close()
            os.remove(output_tar.name)
            return None
        
        try:
            worker_logger.info(f"Requesting debug build artifacts for build {build_id}")
            start_time = time.time()
            
            out_path = client.get_data(
                "debug_build",
                "debug_build_artifacts",
                build_id,
                allow_missing=True,
                out_file_path=output_tar.name
            )
            
            download_time = time.time() - start_time
            if out_path:
                worker_logger.info(f"Download request completed in {download_time:.2f}s for build {build_id}")
            
        except requests.exceptions.HTTPError as e:
            worker_logger.error(f"HTTP error downloading debug artifact for build {build_id}: {e}")
            import traceback
            traceback.print_exc()
            output_tar.close()
            os.remove(output_tar.name)
            return None
        except Exception as e:
            worker_logger.error(f"Unexpected error downloading debug artifact for build {build_id}: {e}")
            output_tar.close()
            os.remove(output_tar.name)
            return None

        if not out_path:
            output_tar.close()
            os.remove(output_tar.name)
            worker_logger.info(f"Debug artifact not yet available for build {build_id}")
            # Still waiting for the debug builds to complete
            return None

        worker_logger.info(f"Successfully downloaded debug artifact for build {build_id} to {out_path}")
        return out_path

    def extract_debug_artifact(self, build_id: str, tar_path: str):
        worker_logger = logging.getLogger(__name__)
        worker_logger.info(f"Starting extraction of debug artifact for build {build_id} from {tar_path}")

        # The extraction directory is: /tmp/all_debug_builds_185846/
        # The extraction directory is created in the constructor of this class
        # We are gonna untar the artifact.tar.gz inside that directory and obtain something like:
        # /tmp/all_debug_builds_185846/<build_id_x>/<ALL_ARTIFACTS>
        extraction_dir = Path(self.all_debug_builds_artifacts_dir) / build_id
        
        try:
            extraction_dir.mkdir(parents=True, exist_ok=True)
            worker_logger.info(f"Created/verified shared directory: {extraction_dir}")
        except Exception as e:
            worker_logger.error(f"Failed to create shared directory {extraction_dir} for build {build_id}: {e}")
            raise

        worker_logger.info(f"Starting tar extraction for build {build_id}")
        start_time = time.time()
        
        # This is gonna extract the content of the tar file into the extraction_dir
        # At the end of this I am gonna have something like:
        #
        # /tmp/all_debug_builds_5123123/<build_id_x>/
        #                                            |- artifacts
        #                                            |- Dockerfile
        #                                            |- ...
        #
        # Remember: The extraction directory is: /tmp/all_debug_builds_185846/
        try:
            extraction_proc = subprocess.Popen(
                ["tar", "-xf", tar_path, "-C", extraction_dir],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )

            # wait for extraction to complete
            stdout, stderr = extraction_proc.communicate()
            extraction_time = time.time() - start_time
            
            if extraction_proc.returncode == 0:
                worker_logger.info(f"Tar extraction completed successfully in {extraction_time:.2f}s for build {build_id}")
            else:
                worker_logger.error(f"Tar extraction failed for build {build_id} with return code {extraction_proc.returncode}")
                worker_logger.error(f"Stderr: {stderr.decode() if stderr else 'No stderr'}")
                raise subprocess.CalledProcessError(extraction_proc.returncode, "tar")
                
        except Exception as e:
            worker_logger.error(f"Exception during tar extraction for build {build_id}: {e}")
            raise
        
        # Clean up the tar file
        try:
            os.remove(tar_path)
            worker_logger.info(f"Cleaned up tar file {tar_path} for build {build_id}")
        except Exception as e:
            worker_logger.warning(f"Failed to clean up tar file {tar_path} for build {build_id}: {e}")

        worker_logger.info(f"Extraction completed successfully for build {build_id}, output directory: {extraction_dir}")
        
        # This is returning the directory containing the artifacts for the specific build
        # that we were downloading, e.g., /tmp/all_debug_builds_185846/<build_id_x>/
        logger.info(f"Returning extraction directory for build {build_id}: {extraction_dir}")
        # Do a quick ls of the directory to verify the contents
        try:
            contents = os.listdir(extraction_dir)
            logger.info(f"Contents of extraction directory for build {build_id}: {contents}")
            worker_logger.info(f"Contents of extraction directory for build {build_id}: {contents}")
        except Exception as e:
            worker_logger.error(f"Failed to list contents of extraction directory for build {build_id}: {e}")

        return extraction_dir

    def handle_build_configuration(self, build_id: str):
        # Get logger for this worker process
        worker_logger = logging.getLogger(__name__)
        worker_logger.info(f"Worker process started for build {build_id}")
        
        start_time = time.time()
        attempt_count = 0
        
        # TODO maybe add a max limit of time
        # NOTE: it's ok, worst case this component will burn little resources if we get stuck here.
        while True:
            attempt_count += 1
            worker_logger.info(f"Download attempt #{attempt_count} for build {build_id}")
            
            tar_path = self.try_to_download_debug_artifact(build_id)
            if not tar_path:
                worker_logger.info(f"Waiting for debug artifact to be available for build {build_id} (attempt #{attempt_count})")
                time.sleep(60)
                continue
            break

        download_phase_time = time.time() - start_time
        worker_logger.info(f"Download phase completed in {download_phase_time:.2f}s after {attempt_count} attempts for build {build_id}")

        worker_logger.info(f"Starting extraction for build {build_id}")
        extraction_start = time.time()
        
        try:
            # extracted_dir points to the path that contains 
            # the debug build artifacts for this build_id 
            # e.g., /tmp/all_debug_builds_185846/<build_id_x>/
            extracted_dir = self.extract_debug_artifact(build_id, tar_path)
            extraction_time = time.time() - extraction_start
            total_time = time.time() - start_time
            
            worker_logger.info(f"Completed extraction for build {build_id} to {extracted_dir}")
            worker_logger.info(f"Total processing time for build {build_id}: {total_time:.2f}s (download: {download_phase_time:.2f}s, extraction: {extraction_time:.2f}s)")
            
            return (build_id, extracted_dir)
            
        except Exception as e:
            worker_logger.error(f"Failed to extract debug artifact for build {build_id}: {e}")
            return (build_id, None)

    def process_all_builds(self, build_ids: List[str]):
        logger.info(f"Starting processing of {len(build_ids)} builds: {build_ids}")
        start_time = time.time()
        
        # Multi process with logging initializer
        logger.info(f"Creating multiprocessing pool with 8 processes")
        try:
            with multiprocessing.Pool(processes=8, initializer=init_worker_logging) as pool:
                logger.info("Multiprocessing pool created successfully")
                
                # Use imap_unordered to get results as they complete
                result_iterator = pool.imap_unordered(self.handle_build_configuration, build_ids)
                
                completed_count = 0
                successful_count = 0
                failed_count = 0
                
                # Process results as they arrive
                for build_id, extracted_dir in result_iterator:
                    completed_count += 1
                    
                    if extracted_dir:
                        self.extracted_tars[build_id] = extracted_dir
                        successful_count += 1
                        logger.info(f"Build {build_id} completed successfully ({completed_count}/{len(build_ids)}). Extracted to: {extracted_dir}")
                    else:
                        self.extracted_tars[build_id] = None
                        failed_count += 1
                        logger.error(f"Build {build_id} failed ({completed_count}/{len(build_ids)})")
                    
                    logger.info(f"Progress: {completed_count}/{len(build_ids)} completed ({successful_count} successful, {failed_count} failed)")
                
            total_time = time.time() - start_time
            logger.info(f"All builds processed in {total_time:.2f}s")
            logger.info(f"Final results: {successful_count} successful, {failed_count} failed")
            logger.info(f"Extracted tars dictionary: {self.extracted_tars}")
            
            # OK, now that we have downloaded ALL the debug build artifacts, let's
            # move around folder to re-create the expected structure.
            # For every build we have downloaded, we are making a copy of the folder oss_fuzz_repo_path
            # and we are gonna copy inside ALL the content of the respective debug build artifact.
            # e.g.,
            # oss_fuzz_repo_path = /shared/discoveryguy/tmp.12345/
            # build_ids: build_x, build_y, build_z
            # self.all_debug_builds_artifacts_dir = /tmp/all_debug_builds_185846/<build_x>
            #                                                                   /<build_y>
            #                                                                   /<build_z>
            # The expected structure is:
            # /shared/discoveryguy/tmp.12345/<build_x>/projects/<project_name>/artifacts
            # /shared/discoveryguy/tmp.12345/<build_y>/projects/<project_name>/artifacts
            # /shared/discoveryguy/tmp.12345/<build_z>/projects/<project_name>/artifacts
            # 

            for build_id in build_ids:
                # Create the /shared/discoveryguy/tmp.12345/<build_x>/
                new_oss_fuzz_debug_target_folder = os.path.join(self.oss_fuzz_debug_targets_folder, build_id)
                os.makedirs(new_oss_fuzz_debug_target_folder)
                # Now we have the directory /shared/discoveryguy/tmp.12345/<build_x>/
                
                # Next step: copt ALL the content of the self.oss_fuzz_repo_path inside 
                # /shared/discoveryguy/tmp.12345/<build_x>/
                subprocess.run([
                    "rsync", "-ra", f"{self.oss_fuzz_repo_path}/",
                    new_oss_fuzz_debug_target_folder,
                ], check=True)

                try:
                    contents = os.listdir(new_oss_fuzz_debug_target_folder)
                    logger.info(f"Contents of new_oss_fuzz_debug_target_folder: {contents}")
                except Exception as e:
                    logger.critical(f"Failed to list contents of new_oss_fuzz_debug_target_folder {new_oss_fuzz_debug_target_folder}: {e}")
                    pass

                # Now we have the directory /shared/discoveryguy/tmp.12345/<build_x>/<projects>/<project_name>/
                # Finally, we want to copy the content of the extracted debug build artifact inside:
                # In bash we were doing: rsync -ra "$debug_build"/* "$TMPDIR"/projects/$PROJECT_NAME
                debug_build_artifacts = self.extracted_tars.get(build_id)
                # debug_build_artifacts is, for example, /tmp/all_debug_builds_185846/<build_id_x>
                if debug_build_artifacts:
                    target_directory = os.path.join(new_oss_fuzz_debug_target_folder, "projects", self.project_name)
                    
                    subprocess.run([
                        "rsync", "-ra", f"{debug_build_artifacts}/",
                        target_directory,
                    ], check=True)

                    try:
                        contents = os.listdir(target_directory)
                        logger.info(f"Contents of target_directory: {contents}")
                    except Exception as e:
                        logger.critical(f"Failed to list contents of target_directory {target_directory}: {e}")
                        pass

                else:
                    logger.error(f"Debug build artifacts for build {build_id} are not available. Skipping copy.")
                    continue

            # This function will finally return /shared/discoveryguy/tmp.12345/.
            # This is compatible with the loop in main.py where we iterate over all the folers in 
            # /shared/discoveryguy/tmp.12345/, append the build_id and look for 'projects/<project_name>'
            return self.oss_fuzz_debug_targets_folder
            
        except Exception as e:
            logger.error(f"Error in multiprocessing pool: {e}")
            raise


def main():
    argparser = argparse.ArgumentParser(description="DiscoveryGuy")

    ####### PROJECT INFO #######
    argparser.add_argument("--project_id", required=True)
    # The id of the current discoveryguy (for multi-thread)
    argparser.add_argument("--dg_id", required=False, default=None)
    # The source of the project pre-built
    argparser.add_argument("--project_source", required=False, default=None)
    # The metadata of the target (we need to know the language, name)
    argparser.add_argument("--target_metadata", required=False, default=None)
    ############################

    ####### FUNCTION RESOLVER #######
    # The report of the functions by file index
    argparser.add_argument("--functions_by_file_index", required=False, default=None)
    # The function index as generated by clang-indexer/antlr-indexer
    argparser.add_argument("--function_index", required=False, default=None)
    # The directory where the functions jsons are stored
    argparser.add_argument("--target_functions_jsons_dir", required=False, default=None)
    ###################################

    ####### HARNESS INFO #######
    # Aggregated harness info file
    argparser.add_argument("--aggregated_harness_info_file", required=False, default=None)
    #############################


    ####### TARGET BUILDS (ONLY LOCAL RUNS) #######
    # This is the OSS fuzz repo where we are going to copy the artifacts in
    # /projects/$PROJECT_NAME
    argparser.add_argument("--oss_fuzz_repo_path", required=False, default=None)
    # This is where we are gonna download all the debug artifacts.
    argparser.add_argument("--oss_fuzz_debug_targets_folder", required=False, default=None)
    # HACK for bypass guy here.
    argparser.add_argument("--oss_fuzz_debug_target_folder", required=False, default=None)
    # The root folder where the original sources of the project are
    argparser.add_argument("--oss_fuzz_debug_target_folder_source_root", required=False, default=None)
    # The root folder of the oss-fuzz-target built with coverage
    argparser.add_argument("--oss_fuzz_coverage_target_folder", required=False, default=None)
    # The root folder where the original sources of the project are
    argparser.add_argument("--oss_fuzz_coverage_target_folder_source_root", required=False, default=None)
    # The original source code wihtout any of the patches applied NOTE: only for bypass guy
    argparser.add_argument("--debug_build_artifact", required=False, default=None)
    #############################

    ####### DIFF MODE #######
    # The changed funcion index file
    argparser.add_argument("--changed_function_index", required=False, default=None)
    # The directory where the changed functions jsons are stored
    argparser.add_argument("--changed_functions_jsons_dir", required=False, default=None)
    # The diff file to use in delta mode
    argparser.add_argument("--diff_file", required=False, default=None)
    #############################

    ####### CODEQL #######
    # The path to the CodeQL database if we are running locally
    argparser.add_argument('--codeql_db_path', required=False, default=None)
    ######################

    ####### MODES #######
    # The code_swipe report
    argparser.add_argument("--function_ranking", required=False, default=None)
    argparser.add_argument("--pois", required=False, default=None)
    # The SARIF report
    argparser.add_argument("--sarif", required=False, default=None)
    # The SARIF metadata file
    argparser.add_argument("--sarif_meta", required=False, default=None)
    # [BYPASS MODE] The request to the bypass service as genearated by patchers
    argparser.add_argument("--bypass_request", required=False, default=None)
    # [BYPASS MODE] The patch ID to use for the bypass request
    argparser.add_argument("--patch_id", required=False, default=None)
    # [BYPASS MODE] The harness ID to use for the bypass request
    argparser.add_argument("--bypass_harness_id", required=False, default=None)
    # [BYPASS MODE] The name of the sanitizer that was used to produce the bypass request
    argparser.add_argument("--bypass_sanitizer", required=False, default=None)
    ######################

    ####### OUTPUTS #######
    argparser.add_argument('--backup_seeds_vault', required=False, default=None)
    argparser.add_argument('--report_dir', required=False, default=None)
    argparser.add_argument("--crash_dir_pass_to_pov", required=False, default=None)
    argparser.add_argument("--crash_metadata_dir_pass_to_pov", required=False, default=None)
    argparser.add_argument("--bypass_result_dir", required=False, default=None)
    argparser.add_argument("--out_sarif_path", required=False, default=None)
    ######################

    args = argparser.parse_args()

    ####### BUDGET #############
    rand_y = random.randint(0, 10000)
    rand_x = random.randint(0, 10000)
    agentlib.enable_event_dumping(f"/tmp/stats-{args.dg_id}-{rand_y}-{rand_x}/")
    agentlib.set_global_budget_limit(
        price_in_dollars=Config.discoguy_budget_limit,
        exit_on_over_budget=True,
    )
    ############################

    disco_guy_mode = os.getenv("DELTA_MODE", "")
    if disco_guy_mode == "True":
        Config.crs_mode = CRSMode.DELTA
    elif disco_guy_mode == "False":
        Config.crs_mode = CRSMode.FULL
    else:
        logger.critical(f"[CRITICAL] DELTA_MODE is set to {disco_guy_mode}. Please fix it to either True or False.")
        assert False

    disco_guy_from = os.getenv("DISCO_GUY_FROM", "")

    if disco_guy_from == "POIS":
        Config.discoveryguy_mode = DiscoverGuyMode.POIS

    elif disco_guy_from == "SARIF":
        Config.discoveryguy_mode = DiscoverGuyMode.SARIF

    elif disco_guy_from == "BYPASS":
        Config.discoveryguy_mode = DiscoverGuyMode.BYPASS
    
    elif disco_guy_from == "POISBACKDOOR":
        Config.discoveryguy_mode = DiscoverGuyMode.POISBACKDOOR

    elif disco_guy_from == "DIFFONLY":
        Config.discoveryguy_mode = DiscoverGuyMode.DIFFONLY

        # Change the budget for diff only mode
        agentlib.set_global_budget_limit(
            price_in_dollars=Config.discoguy_from_diff_budget_limit,
            exit_on_over_budget=True,
        )
        Config.use_codeql_server = False
    else:
        assert False, f"[CRITICAL] DISCO_GUY_FROM is set to {disco_guy_from}. Please fix it to either POIS, SARIF, BYPASS or POISBACKDOOR"

    local_run = os.getenv("LOCAL_RUN")
    if local_run == "True":
        Config.is_local_run = True
    elif local_run == "False":
        Config.is_local_run = False
    else:
        logger.critical(f"[CRITICAL] LOCAL_RUN is set to {local_run}. Please fix it to either True or False.")
        assert False

    if args.pois and args.sarif:
        raise ValueError("Only one of --pois or --sarif can be provided.")
    if args.diff_file and Config.crs_mode != CRSMode.DELTA:
        raise ValueError("The --diff_file argument is only valid in delta mode.")

    # Open the aggregated harness info file
    with open(args.aggregated_harness_info_file, 'r') as f:
        aggregated_harness_info = yaml.safe_load(f)
    all_sanitizer_builds = aggregated_harness_info['build_configurations']
    
    with open(args.target_metadata, 'r') as f:
        project_yaml = AugmentedProjectMetadata.model_validate(yaml.safe_load(f))
    project_name = project_yaml.get_project_name()
    
    if not Config.is_local_run and Config.discoveryguy_mode != DiscoverGuyMode.BYPASS:
        # NOTE: for bypass guy, we are keyed on the harness, so no need to download the debug artifacts.
        logger.info("=== ⬇️ Starting DebugArtifactDownloader ===")
        downloader = DebugArtifactDownloader(project_name, args.oss_fuzz_debug_targets_folder, args.oss_fuzz_repo_path)
        
        # all_debug_builds is a directory with the following structure:
        # /shared/discoveryguy/tmp.12345/<build_x>/projects/<project_name>/artifacts
        # /shared/discoveryguy/tmp.12345/<build_y>/projects/<project_name>/artifacts
        # /shared/discoveryguy/tmp.12345/<build_z>/projects/<project_name>/artifacts
        all_debug_builds = downloader.process_all_builds(all_sanitizer_builds)
        # Results and extracted_tars should be the same now
        logger.info(f"All debug results at {all_debug_builds}")
        
        try:
            os.system(f"ls -l {all_debug_builds}")
        except Exception as e:
            pass

        # Make sure we have at least one debug artifact
        if not os.listdir(all_debug_builds):
            logger.error("💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥")
            logger.error(f"[CRITICAL] No debug artifacts were downloaded. Please check the logs for errors.")
            logger.error("💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥")
            exit(1)
        logger.info("=== ✅ DebugArtifactDownloader completed successfully ===")
    else:
        logger.info(f"Running in local mode, the debug artifacts are already available in {args.oss_fuzz_debug_targets_folder}")
        all_debug_builds = args.oss_fuzz_debug_targets_folder

    new_args = {
        'local_run': local_run,
        'disco_guy_mode': disco_guy_mode,
        'disco_guy_from': disco_guy_from,
        'project_id': args.project_id,
        'dg_id': args.dg_id,
        'project_source': args.project_source,
        'oss_fuzz_debug_targets_folder': all_debug_builds,
        'oss_fuzz_debug_target_folder': args.oss_fuzz_debug_target_folder,
        'target_metadata': args.target_metadata,
        'target_functions_jsons_dir': args.target_functions_jsons_dir,
        'aggregated_harness_info_file': args.aggregated_harness_info_file,
        'functions_by_file_index': args.functions_by_file_index,
        'changed_functions_jsons_dir': args.changed_functions_jsons_dir,
        'function_index': args.function_index,
        'function_ranking':args.function_ranking,
        'codeql_db_path': args.codeql_db_path,
        'backup_seeds_vault': args.backup_seeds_vault,
        'report_dir': args.report_dir,
        'crash_dir_pass_to_pov': args.crash_dir_pass_to_pov,
        'crash_metadata_dir_pass_to_pov': args.crash_metadata_dir_pass_to_pov,
        'debug_build_artifact': args.debug_build_artifact
    }

    # Add the extra arguments depending on the discoveryguy mode
    if Config.discoveryguy_mode == DiscoverGuyMode.POIS:
        new_args['pois'] = args.pois

    elif Config.discoveryguy_mode == DiscoverGuyMode.SARIF:
        new_args['sarif'] = args.sarif
        new_args['sarif_meta'] = args.sarif_meta
        new_args['sarif_assessment_out_path'] = args.out_sarif_path

    elif Config.discoveryguy_mode == DiscoverGuyMode.BYPASS:
        new_args['bypass_request'] = args.bypass_request
        new_args['bypass_patch_id'] = args.patch_id
        new_args['bypass_result_dir'] = args.bypass_result_dir

    if Config.crs_mode == CRSMode.DELTA:
        new_args['changed_function_index'] = args.changed_function_index
        new_args['diff_file'] = args.diff_file

    logger.info(args)
    

    if Config.discoveryguy_mode != DiscoverGuyMode.BYPASS:
        from discoveryguy.main import main as main_pwn
        main_pwn(**new_args)
    elif Config.discoveryguy_mode == DiscoverGuyMode.BYPASS:
        from discoveryguy.main_bypass import main as main_bypass
        main_bypass(**new_args)
    else:
        raise ValueError(f"[CRITICAL] Unsupported discoveryguy mode: {Config.discoveryguy_mode}")

if __name__ == "__main__":
    with otel_tracer.start_as_current_span("discoveryguy.main") as span:
        main()
        span.set_status(status_ok())
