import argparse
import logging

from backdoorguy.main import main as backdoorguy_main
from crs_telemetry.utils import init_otel, get_otel_tracer, status_ok, init_llm_otel

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

init_otel("backdoorguy", "program_analysis", "llm_program_analysis")
init_llm_otel()
tracer = get_otel_tracer()

def main():
    argparser = argparse.ArgumentParser(description='BackdoorGuy*')

    # ====== REQUIRED ARGUMENTS ======
    argparser.add_argument('--project_id', type=str, required=True, help='Project ID for the OSSFuzz project')
    argparser.add_argument('--project_metadata', type=str, required=True, help='Path to the project metadata YAML file')
    
    argparser.add_argument('--oss_fuzz_project', type=str, required=True, help='Path to the OSSFuzz project directory')
    argparser.add_argument('--oss_fuzz_project_src', type=str, required=True, help='Path to the OSSFuzz project source directory')
    
    argparser.add_argument('--functions_index', type=str, required=True, help='Path to the functions index YAML file')
    argparser.add_argument('--functions_jsons_dir', type=str, required=True, help='Directory containing function JSON files')
    
    argparser.add_argument('--out_path', type=str, required=True, help='Output path for results')
    argparser.add_argument('--local_run', type=str, default='False', help='Run locally or remotely (default: False)')

    # ====== LOGGING CONFIGURATION ======
    args = argparser.parse_args()
    all_args = vars(args)
    logger.info(f"🏁 Running BackdoorGuy with arguments: {all_args}")
    try:
        backdoorguy_main(**all_args)
    except Exception as e:
        logger.error(f"🤡 An error occurred while running BackdoorGuy: {e}")
        raise

if __name__ == '__main__':
    with tracer.start_as_current_span("backdoorguy.main") as span:
        main()
        span.set_status(status_ok())