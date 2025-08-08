import hashlib
import shutil
import yaml
import time
import argparse
import subprocess
import os
import stat
import logging
import json

from pathlib import Path
from typing import Optional

from rich.logging import RichHandler

from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject, InstrumentedOssFuzzProject
from shellphish_crs_utils.models import RunPoVResult, RepresentativeCrashingInputMetadata, PoVCrashReport, CrashingInputMetadata

FORMAT = "%(message)s"
logging.basicConfig(level="INFO", format=FORMAT, datefmt="[%X]")

log = logging.getLogger("povguy")
#log.propagate = False

log.addHandler(RichHandler())


def find_vmlinux(project_dir: Path) -> Optional[Path]:
    vmlinux_path = None
    for root, _, files in os.walk(project_dir):
        root_path = Path(root)
        files_set = set(files)
        if 'vmlinux' in files_set:
            vmlinux_path = root_path / 'vmlinux'
            vmlinux_path = vmlinux_path.resolve()
            if 'Kconfig' in files_set and 'Kbuild' in files_set:
                return vmlinux_path.resolve()

    return vmlinux_path


def decode_stacktrace(vmlinux_path: Path, orig_kasan_content: bytes) -> Optional[str]:
    try:
        current_file_path = Path(__file__).absolute()
        current_dir = current_file_path.parent

        decode_stacktrace_sh = current_dir / 'kernel_scripts' / 'decode_stacktrace.sh'
        decodecode = current_dir / 'kernel_scripts' / 'decodecode'

        os.chmod(decode_stacktrace_sh, stat.S_IXUSR | stat.S_IRUSR | stat.S_IWUSR)
        os.chmod(decodecode, stat.S_IXUSR | stat.S_IRUSR | stat.S_IWUSR)

        result = subprocess.run([decode_stacktrace_sh, vmlinux_path], input=orig_kasan_content.decode(), text=True, capture_output=True)
        log.info("running decode_stacktrace.sh, stderr: %s", result.stderr)

        if result.returncode == 0:
            return result.stdout
        else:
            log.error("Failed to decode stacktrace: %s", result.stderr)
    except Exception as e:
        log.error("Failed to decode stacktrace with exception: %s", e)
    return None

def kasan_add_lineno(raw_report: bytes, project_dir: Path) -> str:
    vmlinux_path = find_vmlinux(project_dir)
    if vmlinux_path is None:
        return raw_report
    try:
        report_with_lineno = decode_stacktrace(vmlinux_path, raw_report)
        if report_with_lineno:
            return report_with_lineno
        log.error("Failed to decode stacktrace for %s", raw_report)
    except Exception as e:
        log.error("Failed to decode stacktrace for %s: %s", raw_report, e)

    return raw_report

def calculate_md5(file_path: Path) -> str:
    hash_md5 = hashlib.md5()
    if file_path.exists():
        with file_path.open("rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    return f"File {file_path} does not exist"


def run_pov(base_meta_path: Path, 
            output_run_pov_results_path: Path, 
            output_crash_report_path: Path, 
            out_representative_crash: Path, 
            out_representative_crash_metadata: Path, 
            project_dir: Path, 
            harness_name: str, 
            pov_path: Path, 
            crash_id: str, 
            expect_crashing=True, 
            timeout=None, 
            retry_count=5):

    log.info("Running pov %s with harness %s", pov_path, harness_name)
    with open(base_meta_path, 'r') as f:
        base_meta = yaml.safe_load(f)
    crash_metadata = CrashingInputMetadata(**base_meta)

    cp = OSSFuzzProject(project_dir)
    cp.build_runner_image()
    log.info("md5: %s", calculate_md5(pov_path))

    # try:
    #     env_docker_path = cp.project_path / '.env.docker'

    #     # Set java memory limits to 80% of 1GB (The tasks max memory quota)
    #     try:
    #         subprocess.run(["sed", "-i", "/JAVA_OPTS/d", str(env_docker_path)], check=True)
    #     except Exception as e:
    #         log.error(f"Failed to remove JAVA_OPTS: %s", e)

    #     with env_docker_path.open("a") as f:
    #         f.write("\nJAVA_OPTS=-Xmx820m\n")

    # except Exception as e:
    #     log.error("Failed to set JAVA_OPTS: %s", e)

    # Run the pov
    consistently_triggered_sanitizers = None
    triggered_sanitizer_history = []
    for idx in range(retry_count):
        start = time.time()
        run_pov_result: RunPoVResult = cp.run_pov(harness_name, data_file=pov_path, timeout=timeout)
        log.info("Run  %s took %s seconds!", idx, time.time() - start)
        pov = run_pov_result.pov

        log.info("#%s: POV %s triggered sanitizers: %s", idx, pov_path, pov.triggered_sanitizers)
        if expect_crashing and not pov.crash_report:
            # crash report is a dict, don't want to break the format
            log.critical("#%s: POV %s did not crash!!!", idx, pov_path)
            log.critical("#%s: POV %s stdout: %s", idx, pov_path, run_pov_result.stdout)
            log.critical("#%s: POV %s stderr: %s", idx, pov_path, run_pov_result.stderr)
            triggered_sanitizer_history.append([])
            consistently_triggered_sanitizers = set()
            break
            # TODO: maybe a better way to handle this, since a timeout may lead to no crash
        elif pov.crash_report:
            log.info("#%s: POV %s did crash!!!", idx, pov_path)
            log.info("#%s: POV %s stdout: %s", idx, pov_path, run_pov_result.stdout)
            log.info("#%s: POV %s stderr: %s", idx, pov_path, run_pov_result.stderr)

        if idx == 0:
            consistently_triggered_sanitizers = set(pov.triggered_sanitizers)
        else:
            consistently_triggered_sanitizers &= set(pov.triggered_sanitizers)

        if len(consistently_triggered_sanitizers) == 0:
            log.error("No valid sanitizers found")
            log.error("Run results: %s", run_pov_result)
            exit(0)

        triggered_sanitizer_history.append(list(sorted(set(pov.triggered_sanitizers))))

    log.info("CONSISTENTLY Triggered sanitizers: %s", consistently_triggered_sanitizers)

    if find_vmlinux(project_dir):
        raw_kasan_with_lineno = []
        for idx, raw_kasan in enumerate(pov.report.reports):
            raw_kasan_with_lineno.append(kasan_add_lineno(raw_kasan.report, project_dir))
            pov.report.reports[idx].report = raw_kasan_with_lineno[idx]

    all_sanitizers = set([sanitizer for saniset in triggered_sanitizer_history for sanitizer in saniset])
    inconsistent_sanitizers = list(sorted(all_sanitizers - consistently_triggered_sanitizers))
    consistent_sanitizers=list(set(consistently_triggered_sanitizers))

    full_crash_report = run_pov_result.pov.crash_report
    run_pov_result.pov.crash_report = None # for deduping
    run_pov_result.pov.extra_context = None # for deduping
    report = PoVCrashReport(inconsistent_sanitizers=inconsistent_sanitizers,
                            consistent_sanitizers=consistent_sanitizers,
                            **crash_metadata.model_dump(),
                            **run_pov_result.pov.model_dump(),
                            )

    crash_report = yaml.dump(json.loads(report.model_dump_json())).encode()
    crash_report_md5 = hashlib.md5(crash_report).hexdigest()

    run_pov_result.pov.crash_report = full_crash_report # restore for full info

    representative_crashing_meta = RepresentativeCrashingInputMetadata(run_pov_result=run_pov_result, 
                                                                       original_crash_id=crash_id, 
                                                                       crash_report_id=crash_report_md5,
                                                                       sanitizer_history=triggered_sanitizer_history,
                                                                       **report.model_dump()
                                                                       )

    representative_crashing_meta = json.loads(representative_crashing_meta.model_dump_json())
    # first, copy the pov to the output directory
    shutil.copy(pov_path, out_representative_crash)
    # then, copy the metadata to the output directory
    with open(out_representative_crash_metadata, 'w') as f:
        yaml.dump(representative_crashing_meta, f)

    with open(output_run_pov_results_path, 'w') as f:
        yaml.dump(representative_crashing_meta, f)

    with open(output_crash_report_path, 'wb') as f:
        f.write(crash_report)

def main():
    parser = argparse.ArgumentParser(description="Run a POV with a harness")
    parser.add_argument("--timeout", type=int, default=300, help="The timeout for the POV")
    parser.add_argument("--expect-crash", type=bool, help="Expect the POV to crash")
    parser.add_argument("--crash-id", type=str, help="The crash id")
    parser.add_argument("--project-dir", type=Path, help="The directory of the oss fuzz project")
    parser.add_argument("--harness-name", type=str, help="The harness name")
    parser.add_argument("--pov-path", type=Path, help="The crashing input path")
    parser.add_argument("--base-meta-path", type=Path, help="Crash metadata yaml file")
    parser.add_argument("--out-report-path", type=Path, help="The output path")
    parser.add_argument("--out-run-pov-results-path", type=Path, help="The output path")
    parser.add_argument("--out-representative-crash", type=Path, help="The output path")
    parser.add_argument("--out-representative-crash-metadata", type=Path, help="The output path")

    args = parser.parse_args()

    run_pov(
        base_meta_path=args.base_meta_path,
        output_run_pov_results_path=args.out_run_pov_results_path,
        output_crash_report_path=args.out_report_path,
        out_representative_crash=args.out_representative_crash,
        out_representative_crash_metadata=args.out_representative_crash_metadata,
        project_dir=args.project_dir,
        harness_name=args.harness_name,
        pov_path=args.pov_path,
        crash_id=args.crash_id,
        timeout=args.timeout,
        retry_count=5
    )
    # retry_count is set to 5 because kernel run_pov may take a long time to run, for tipc, ~2 min for each run
if __name__ == '__main__':
    main()
