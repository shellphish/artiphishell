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

def run_build_check(artifacts_path: Path, sanitizer: str, timeout: Optional[int] = None):
    try:
        project = OSSFuzzProject(artifacts_path)
        project.build_runner_image()


        with telemetry_tracer.start_as_current_span("povguy.check_base_run_success") as span:
            start = time.time()
            result = project.run_ossfuzz_build_check(
                sanitizer, fuzzing_engine='libfuzzer'
            )
            log.info("Run took %s seconds!",time.time() - start)
            log.info("Build check result: %s", str(result))
            if not result.all_passed:
                log.info("❌ Build check failed:")
                log.info("=== STDOUT ===")
                log.info(result.stdout)
                log.info("=== STDERR ===")
                log.info(result.stderr)
                log.info("=== END ===")
            else:
                log.info("✅ Build check passed")

            return result.all_passed
    except Exception as e:
        import traceback
        traceback.print_exc()
        log.warning("Failed to run the base project: %s", str(e))
        return False

def main():
    parser = argparse.ArgumentParser(description='Verify base run')
    parser.add_argument('--sanitizer', required=True, help='Sanitizer name')
    parser.add_argument('--output', required=True, help='Output YAML file path')
    parser.add_argument('--artifacts-path', required=True, help='Artifacts path')
    
    args = parser.parse_args()
    
    try:
        # Run the base project with 60 second timeout
        success = run_build_check(Path(args.artifacts_path), args.sanitizer, timeout=60)
        
        if success:
            result = "runs: true"
        else:
            result = "runs: false"
            
    except Exception as e:
        log.warning("Exception during base run: %s", str(e))
        result = "runs: false"
    
    # Write result to output file
    with open(args.output, 'w') as f:
        f.write(result)

if __name__ == "__main__":
    main()