#!/usr/bin/env python3

from shellphish_crs_utils.models.target import HarnessInfo
import yaml
import time
import argparse
import subprocess
import os
import stat
import tempfile
import logging
import json

from pathlib import Path
from typing import Optional

from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject, InstrumentedOssFuzzProject

from crs_telemetry.utils import (
    init_otel,
    get_otel_tracer,
    status_ok,
    init_llm_otel,
    get_current_span,
    status_error,
)

init_otel("povguy", "testing", "base_runs_successfully")
init_llm_otel()
telemetry_tracer = get_otel_tracer()

log = logging.getLogger(__name__)

def run_base_project(artifacts_path: Path, harness_name: str, pov_path: Path, timeout: Optional[int] = None):
    try:
        cp_base = OSSFuzzProject(artifacts_path)
        cp_base.build_runner_image()


        with telemetry_tracer.start_as_current_span("povguy.check_base_run_success") as span:
            start = time.time()
            base_run_pov_result = cp_base.run_pov(
                harness_name, data_file=pov_path, timeout=timeout
            )
            log.info("Run took %s seconds!",time.time() - start)
            return True
    except Exception as e:
        import traceback
        traceback.print_exc()
        log.warning("Failed to run the base project: %s", str(e))
        return False

def main():
    parser = argparse.ArgumentParser(description='Verify base run')
    parser.add_argument('--harness', required=True, help='Harness name')
    parser.add_argument('--output', required=True, help='Output YAML file path')
    parser.add_argument('--artifacts-path', required=True, help='Artifacts path')
    
    args = parser.parse_args()
    
    # Create a temporary file with "hello world"
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as tmp_file:
        tmp_file.write("hello world")
        tmp_pov_path = Path(tmp_file.name)
    
    try:
        # Run the base project with 60 second timeout
        success = run_base_project(Path(args.artifacts_path), args.harness, tmp_pov_path, timeout=60)
        
        if success:
            result = "runs: true"
        else:
            result = "runs: false"
            
    except Exception as e:
        log.warning("Exception during base run: %s", str(e))
        result = "runs: false"
    finally:
        # Clean up temporary file
        try:
            os.unlink(tmp_pov_path)
        except:
            pass
    
    # Write result to output file
    with open(args.output, 'w') as f:
        f.write(result)

if __name__ == "__main__":
    main()