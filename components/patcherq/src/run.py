
import agentlib
import argparse
import os
import logging
import yaml

# from patcherq.main import main as pq_main
from patcherq.main import main as pq_main
from shellphish_crs_utils.models.oss_fuzz import AugmentedProjectMetadata
from shellphish_crs_utils.models.crs_reports import PatchRequestMeta

from crs_telemetry.utils import init_otel, get_otel_tracer, status_ok, init_llm_otel

from patcherq.config import Config, PatcherqMode, CRSMode

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

init_otel("patcherq", "patch_generation", "llm_patch_generation")
init_llm_otel()
tracer = get_otel_tracer()

def main():
    argparser = argparse.ArgumentParser(description='PatcherQ*')

    agentlib.enable_event_dumping("/tmp/stats/")
    

    # ====== REQUIRED ARGUMENTS ======
    argparser.add_argument('--crs_mode', choices=['full', 'delta'], required=True)
    argparser.add_argument('--patcherq_mode', choices=['SARIF', 'PATCH', 'REFINE'], required=True)
    argparser.add_argument('--project_id', required=True)
    argparser.add_argument('--target_root', required=True)
    argparser.add_argument('--source_root', required=True)
    argparser.add_argument('--project_metadata', required=True)
    argparser.add_argument('--function_index', required=True)
    argparser.add_argument('--patch_output_path', required=True)
    argparser.add_argument('--patch_metadata_output_path', required=True)
    argparser.add_argument('--target_functions_jsons_dir', required=True)
    argparser.add_argument('--functions_by_file_index', required=True)

    # This is the request from pG (not needed for SARIF mode)
    argparser.add_argument('--patch_request_meta', required=False)
    # This is the poi report (not needed for SARIF mode)
    argparser.add_argument('--poi_report', required=False)
    # This is the POI report ID (not needed for SARIF mode)
    argparser.add_argument('--poi_report_id', required=False)
    # This is the crashing input path (not needed for SARIF mode)
    argparser.add_argument('--crashing_input_path', required=False)
    
    argparser.add_argument('--sarif_output_path', required=False)
    argparser.add_argument('--dyva_report', required=False)
    argparser.add_argument('--codeql_db_path', required=False, default=None)
    argparser.add_argument('--codeql_db_ready', required=False, default=None)

    # This is the SARIF input path (not needed for PATCH|REFINE mode)
    argparser.add_argument('--sarif_input_path', required=False)
    argparser.add_argument('--sarif_id' , required=False)
    
    # These are only valid in delta mode 
    argparser.add_argument("--changed_functions_index", required=False, default=None)
    argparser.add_argument("--changed_functions_jsons_dir", required=False, default=None)
    argparser.add_argument("--diff_file", required=False, default=None)

    argparser.add_argument('--bypass_request_output_path', required=False)

    argparser.add_argument('--patched_artifacts_dir', required=False)
    argparser.add_argument('--patched_artifacts_dir_lock', required=False)

    args = argparser.parse_args()
    
    if args.crs_mode == 'delta':
        Config.crs_mode = CRSMode.DELTA
        assert args.diff_file is not None
        assert args.changed_functions_index is not None
        assert args.changed_functions_jsons_dir is not None
    
    if args.patcherq_mode == "PATCH":
        Config.patcherq_mode = PatcherqMode.PATCH
        # Open the poi report and grab the sanitizer in scope here
        with open(args.poi_report, 'r') as f:
            poi_report = yaml.load(f, Loader=yaml.FullLoader)
        
        sanitizer_to_build_with = poi_report['sanitizer']
        assert(sanitizer_to_build_with is not None)

        # Validate the patch request metadata
        
        with open(args.patch_request_meta, 'r') as f:
            patch_request_meta = PatchRequestMeta.model_validate(yaml.safe_load(f))

        # A few assertions to validate everything is sane 
        assert patch_request_meta.request_type == "patch", "Invalid patch request type. Expected 'patch'."
        assert patch_request_meta.patch_id == None, "The patch_id for a new patch should be None."
        assert patch_request_meta.poi_report_id == args.poi_report_id, "The POI report ID in the patch request metadata does not match the provided POI report ID." 

    elif args.patcherq_mode == "SARIF":
        Config.patcherq_mode = PatcherqMode.SARIF
        # In case of SARIF input, we need to get the sanitizer from the project metadata
        # file, as the SARIF report does not contain this information.
        with open(args.project_metadata, 'r') as f:
            project_yaml = AugmentedProjectMetadata.model_validate(yaml.safe_load(f))
        sanitizer_to_build_with = project_yaml.sanitizers[0]
        assert(sanitizer_to_build_with is not None)
        
    elif args.patcherq_mode == "REFINE":
        Config.patcherq_mode = PatcherqMode.REFINE
        # Open the offending (failing) poi report and grab the sanitizer in scope here
        # NOTE: we expect that to be the same sanitizer as the previously mitigated POIs.
        with open(args.poi_report, 'r') as f:
            poi_report = yaml.load(f, Loader=yaml.FullLoader)
        sanitizer_to_build_with = poi_report['sanitizer']
        assert(sanitizer_to_build_with is not None)
    
        with open(args.patch_request_meta, 'r') as f:
            patch_request_meta = PatchRequestMeta.model_validate(yaml.safe_load(f))
        
        # DEBUG-DEV only
        # patch_request_meta.patch_id = "a0bf79c1ab93c60d896ca95aacde84fe"
        # patch_request_meta.request_type = "refine"
        # patch_request_meta.bucket_id = "57d9e1f9879582349407bfc9fa046b17"

        assert patch_request_meta.request_type == "refine", "Invalid patch request type. Expected 'refine'."
        assert patch_request_meta.patch_id != None, "The patch_id for a refinement patch should not be None."
        assert patch_request_meta.poi_report_id == args.poi_report_id, "The POI report ID in the patch request metadata does not match the provided POI report ID." 

    else:
        raise ValueError(f"Invalid patcherq_mode: {args.patcherq_mode}. Please use either 'POIS' or 'SARIF' or 'REFINE")
        
    myargs = {
        'project_id': args.project_id,
        'project_yaml': args.project_metadata,
        'source_root': args.source_root,
        'target_root': args.target_root,
        'function_index': args.function_index,
        # 'sanitizer_string': args.sanitizer_string,
        'patch_output_path': args.patch_output_path,
        'patch_metadata_output_path': args.patch_metadata_output_path,
        'target_functions_jsons_dir': args.target_functions_jsons_dir,
        'functions_by_file_index': args.functions_by_file_index,
        'sanitizer_to_build_with': sanitizer_to_build_with,
        'codeql_db_path': args.codeql_db_path,
        'codeql_db_ready': args.codeql_db_ready,
        'patched_artifacts_dir': args.patched_artifacts_dir,
        'patched_artifacts_dir_lock': args.patched_artifacts_dir_lock
    }
    
    # Adding the optional arguments if present
    if args.poi_report_id:
        myargs['poi_report_id'] = args.poi_report_id
    if args.poi_report:
        myargs['poi_report'] = args.poi_report
    if args.crashing_input_path:
        myargs['crashing_input_path'] = args.crashing_input_path
    if args.sarif_output_path:
        myargs['sarif_output_path'] = args.sarif_output_path
    if args.dyva_report:
        myargs['dyva_report'] = args.dyva_report
    if args.bypass_request_output_path:
        myargs['bypass_request_output_path'] = args.bypass_request_output_path

    if args.diff_file:
        myargs['diff_file'] = args.diff_file
    if args.changed_functions_index:
        myargs['changed_functions_index'] = args.changed_functions_index
    if args.changed_functions_jsons_dir:
        myargs['changed_functions_jsons_dir'] = args.changed_functions_jsons_dir

    if os.getenv("LOCAL_RUN") == "True":
        logger.info("[DEBUG] LOCAL_RUN is set to True")
        myargs['use_task_service'] = False
        myargs['local_run'] = True
    else:
        logger.info("[DEBUG] LOCAL_RUN is set to False")
        myargs['use_task_service'] = True
        myargs['local_run'] = False

    logger.info("%s", myargs)
    
    if Config.patcherq_mode == PatcherqMode.PATCH:
        myargs['patch_request_meta'] = patch_request_meta
        myargs['bucket_id'] = patch_request_meta.bucket_id
    
    elif Config.patcherq_mode == PatcherqMode.SARIF:
        myargs['sarif_input_path'] = args.sarif_input_path
        myargs['sarif_id'] = args.sarif_id
    
    elif Config.patcherq_mode == PatcherqMode.REFINE:
        myargs['patch_request_meta'] = patch_request_meta
        # NOTE: in refinement mode, the patch_id is the failing patch_id
        myargs['failing_patch_id'] = patch_request_meta.patch_id
        # NOTE: the bucket_id is a node we can use to grab all the related 
        myargs['bucket_id'] = patch_request_meta.bucket_id
        try:
            myargs['failed_functionality'] = patch_request_meta.failed_functionality
        except Exception as e:
            myargs['failed_functionality'] = None
    else:
        raise ValueError(f"Invalid patcherq_mode: {args.patcherq_mode}. Please use either 'PATCH' or 'SARIF' or 'REFINE'.")
    
    # Are we running in CI?
    if os.getenv("ARTIPHISHELL_GLOBAL_ENV_IS_CI_LLM_BUDGET") == "true":
        myargs['ci_run'] = True
        logger.info("[DEBUG] Running in CI, setting up custom LLM budget for patching...")
        # Set a different budget for the LLM for CI.
        agentlib.set_global_budget_limit(
            lite_llm_budget_name='patching-budget'
        )
    else:
        logger.info("[DEBUG] NOT Running in CI...")
        myargs['ci_run'] = False

    try:
        # load the codeql_db_ready 
        with open(args.codeql_db_ready, 'r') as f:
            codeql_db_ready_meta = yaml.safe_load(f)
            if codeql_db_ready_meta['success']:
                Config.use_codeql_server = True
                logger.info("🤠 CodeQL server is up!")
            else:
                Config.use_codeql_server = False
                logger.warning("😮‍💨 CodeQL server is broken, proceeding without it...")
    except Exception as e:
        logger.error(f"Error loading codeql_db_ready metadata: {e}. Whatever.")
        pass

    pq_main(**myargs)

if __name__ == "__main__":
    with tracer.start_as_current_span("patcherq.main") as span:
        main()
        span.set_status(status_ok())