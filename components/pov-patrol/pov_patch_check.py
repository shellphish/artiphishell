import os
import logging
import argparse
import tempfile
import shutil
import time
import signal
from multiprocessing import cpu_count, Pool

from pathlib import Path

from alive_progress import alive_bar

from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject
from shellphish_crs_utils.pydatatask import PDClient
from shellphish_crs_utils.models.crs_reports import RunPoVResult, PoVReport

from shellphish_crs_utils.oss_fuzz.target_runner_service import BuildServiceRequest

from analysis_graph.models import crashes as analysis_graph_patches
from analysis_graph.models.harness_inputs import HarnessInputNode

logger = logging.getLogger("PoV Patrol")
logger.setLevel(logging.INFO)

SHARED_ARTIFACTS_DIR = Path(f"/shared/pov_patrol") / os.environ.get('PROJECT_ID','all')
SHARED_ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

def get_patch_artifacts(patch_key: str, build_request_id: str, pd_client: PDClient) -> Path:
    artifacts_dir = SHARED_ARTIFACTS_DIR / str(patch_key)
    if artifacts_dir.exists():
        return artifacts_dir

    if not build_request_id:
        raise ValueError(f"Patch {patch_key} has no build request id")

    logger.info("Getting patch artifacts for %s, build request id %s", patch_key, build_request_id)
    for _ in range(3):
        try:
            if artifacts_dir.exists():
                shutil.rmtree(artifacts_dir, ignore_errors=True)
            artifacts_dir.mkdir(parents=True, exist_ok=True)

            with tempfile.TemporaryDirectory() as tmp_dir:
                out_file_path = Path(tmp_dir) / "build_artifacts.tar.gz"
                BuildServiceRequest.keyed_download_build_artifacts_tar(
                    client=pd_client,
                    request_id=build_request_id,
                    out_file_path=out_file_path
                )

                shutil.unpack_archive(out_file_path, artifacts_dir)
            assert artifacts_dir.exists()
            break
        except AssertionError as e:
            logger.error("Error getting patch artifacts for %s: %s", patch_key, e, exc_info=True)
            time.sleep(10)
    else:
        raise ValueError(f"Failed to get patch artifacts for {patch_key}")

    return artifacts_dir

def check_if_pov_is_already_mitigated(pov_report_node: analysis_graph_patches.PoVReportNode, patch: analysis_graph_patches.GeneratedPatch):
    if patch.mitigated_povs.is_connected(pov_report_node):
        logger.info("PoV %s is already connected to patch %s", pov_report_node.key, patch.patch_key)
        return True
    return False

def compare_pov_to_patch(oss_fuzz_project: OSSFuzzProject, 
                         pov_report_id: str, 
                         patch_key: str, 
                         harness_name: str,
                         sanitizer: str,
                         crashing_input: Path):
    """
    Compare a PoV report to a patch.
    Whether the PoV report is mitigated or not is determined by the patch and added to the analysis graph.

    Args:
        oss_fuzz_project: The OSS-Fuzz project.
        pov_report_node: The PoV report node.
        patch: The patch to compare the PoV report to.
        crashing_input: The crashing input to use for the PoV report.

    Returns:
        True if the PoV report is mitigated, False otherwise.
    """

    try:
        start_time = time.time()
        run_pov_result: RunPoVResult = oss_fuzz_project.run_pov(
            harness=harness_name,
            data_file=crashing_input,
            sanitizer=sanitizer,
            timeout=110,
            losan=False,
        )
        logger.info("Time taken to run PoV: %s seconds", time.time() - start_time)
    except Exception as e:
        logger.error("Error running PoV %s for patch %s: %s", pov_report_id, patch_key, e, exc_info=True)
        return None

    # if not run_pov_result.task_success:
    #     logger.error("Error running pov for %s: %s", patch.patch_key, run_pov_result.stderr, exc_info=True)
    #     return

    has_crash = run_pov_result.pov is not None and run_pov_result.pov.crash_report is not None

    if has_crash:
        start_time = time.time()
        logger.info("PoV %s is not mitigated for patch %s", pov_report_id, patch_key)
        logger.info("Time taken to connect non-mitigated PoV to patch: %s seconds", time.time() - start_time)
        return False
    else:
        start_time = time.time()
        logger.info("PoV %s is mitigated for patch %s", pov_report_id, patch_key)
        logger.info("Time taken to connect mitigated PoV to patch: %s seconds", time.time() - start_time)
        return True


def compare_pov_to_patches(oss_fuzz_project: OSSFuzzProject, pov_report_id: str, crashing_input: Path):
    start_time = time.time()
    available_patches: list[analysis_graph_patches.GeneratedPatch] = analysis_graph_patches.GeneratedPatch.nodes.filter(
        pdt_project_id=oss_fuzz_project.project_id
    ).all()
    logger.info("Time taken to get available patches: %s seconds", time.time() - start_time)

    start_time = time.time()
    pov_report_node: analysis_graph_patches.PoVReportNode = analysis_graph_patches.PoVReportNode.nodes.get_or_none(key=pov_report_id, pdt_project_id=oss_fuzz_project.project_id)
    assert pov_report_node is not None, f"PoV report {pov_report_id} not found in graph"
    logger.info("Time taken to get PoV report node: %s seconds", time.time() - start_time)

    harness_name = pov_report_node.content.get('cp_harness_name')
    sanitizer = pov_report_node.content.get('sanitizer')
    if not harness_name:
        logger.error("PoV %s has no harness name: %s", pov_report_id, pov_report_node.content)
        return
    if not sanitizer:
        logger.error("PoV %s has no sanitizer: %s", pov_report_id, pov_report_node.content)
        return

    assert oss_fuzz_project.pdclient is not None, "PDClient is not set"

    orig_start_time = time.time()
    with alive_bar(len(available_patches), title='Comparing PoV to patches', bar='fish') as bar:
        for patch in available_patches:
            try:
                if patch.pdt_project_id != oss_fuzz_project.project_id:
                    logger.info("Patch %s is not in project %s", patch.patch_key, oss_fuzz_project.project_id)
                    continue

                build_request_id = patch.extra_metadata.get('build_request_id')
                if not build_request_id:
                    logger.error("Patch %s has no build request id", patch.patch_key)
                    continue

                if patch.mitigated_povs.is_connected(pov_report_node) or patch.non_mitigated_povs.is_connected(pov_report_node):
                    logger.info("PoV %s is already connected to patch %s", pov_report_node.key, patch.patch_key)
                    continue

                try:
                    start_time = time.time()
                    patch_artifacts_dir = get_patch_artifacts(str(patch.patch_key), build_request_id, oss_fuzz_project.pdclient)
                    logger.info("Time taken to get patch artifacts: %s seconds", time.time() - start_time)
                except Exception as e:
                    logger.error("Error getting patch artifacts for %s: %s", patch.patch_key, e, exc_info=True)
                    continue

                with tempfile.TemporaryDirectory(dir=SHARED_ARTIFACTS_DIR) as tmp_dir:
                    try:
                        shutil.copytree(oss_fuzz_project.project_path, tmp_dir, dirs_exist_ok=True, symlinks=True, ignore_dangling_symlinks=True)
                    except FileNotFoundError as e:
                        logger.error("Error copying OSS-Fuzz project folder for %s: %s", oss_fuzz_project.project_id, e, exc_info=True)
                    except shutil.Error as e:
                        logger.error("Error copying OSS-Fuzz project folder for %s: %s", oss_fuzz_project.project_id, e, exc_info=True)

                    tmp_oss_fuzz_project = OSSFuzzProject(
                        project_id=oss_fuzz_project.project_id,
                        oss_fuzz_project_path=Path(tmp_dir),
                        use_task_service=True
                    )
                    try:
                        shutil.copytree(patch_artifacts_dir, tmp_oss_fuzz_project.artifacts_dir, dirs_exist_ok=True, symlinks=True, ignore_dangling_symlinks=True)
                    except FileNotFoundError as e:
                        logger.error("Error copying patch artifacts for %s: %s", patch.patch_key, e, exc_info=True)
                    except shutil.Error as e:
                        logger.error("Error copying patch artifacts for %s: %s", patch.patch_key, e, exc_info=True)


                    was_mitigated = None
                    for _ in range(3):
                        was_mitigated = compare_pov_to_patch(tmp_oss_fuzz_project, pov_report_id, str(patch.patch_key), harness_name, sanitizer, crashing_input)
                        if was_mitigated is not None:
                            break
                        logger.info("Retrying PoV %s for patch %s", pov_report_id, patch.patch_key)

                if was_mitigated is None:
                    continue

                if was_mitigated:
                    if not patch.mitigated_povs.is_connected(pov_report_node):
                        patch.mitigated_povs.connect(pov_report_node)
                else:
                    if not patch.non_mitigated_povs.is_connected(pov_report_node):
                        patch.non_mitigated_povs.connect(pov_report_node)
                patch.save()
            except Exception as e:
                logger.error("Error processing PoV %s for patch %s: %s", pov_report_id, patch.patch_key, e, exc_info=True)
            finally:
                bar()

    logger.info("Time taken to compare PoV to patches: %s seconds", time.time() - orig_start_time)
    pov_report_node.finished_pov_patrol = True
    pov_report_node.save()

def process_pov_report_wrapper(args: tuple[OSSFuzzProject, str, str, Path, str, str]) -> tuple[str, str, bool]:
    """Wrapper function to unpack arguments for multiprocessing."""
    oss_fuzz_project, pov_report_id, patch_key, crashing_input, sanitizer, harness_name = args
    return process_pov_report(oss_fuzz_project, pov_report_id, patch_key, crashing_input, sanitizer, harness_name)

def process_pov_report(oss_fuzz_project: OSSFuzzProject, pov_report_id: str, patch_key: str, crashing_input: Path, sanitizer: str, harness_name: str) -> tuple[str, str, bool]:
    """
    Process a single PoV report against a patch with a 30-second timeout.
    This function is designed to be run in parallel.
    
    Args:
        oss_fuzz_project: The OSS-Fuzz project.
        pov_report_node: The PoV report node to process.
        patch_node: The patch node to compare against.
    
    Returns:
        tuple: (pov_report_node.key, success_count, error_count) for progress tracking
    """
    
    # Set up signal-based timeout for this individual task
    def timeout_handler(signum, frame):
        raise TimeoutError(f"Task timeout for PoV {pov_report_id}")
    
    was_mitigated = None
    should_retry = False
    with tempfile.TemporaryDirectory(dir=SHARED_ARTIFACTS_DIR) as tmp_dir:
        shutil.copytree(oss_fuzz_project.project_path, tmp_dir, dirs_exist_ok=True, symlinks=True, ignore_dangling_symlinks=True)
        oss_fuzz_project = OSSFuzzProject(
            project_id=oss_fuzz_project.project_id,
            oss_fuzz_project_path=Path(tmp_dir),
            use_task_service=True
        )
        for _ in range(3):
            try:
                signal.signal(signal.SIGALRM, timeout_handler)
                signal.alarm(120)  # 30-second timeout for this task
                
                try:
                    was_mitigated = compare_pov_to_patch(oss_fuzz_project, pov_report_id, patch_key, harness_name, sanitizer, crashing_input)
                finally:
                    signal.alarm(0)  # Disable alarm
                            
            except TimeoutError:
                logger.warning("Task timeout of 80 seconds reached for PoV %s", pov_report_id)
            except Exception as e:
                logger.error("Error processing PoV %s: %s", pov_report_id, e, exc_info=True)
            finally:
                signal.alarm(0)
            if was_mitigated is not None:
                break
            logger.info("Retrying PoV %s for patch %s", pov_report_id, patch_key)
        
    return (pov_report_id, patch_key, was_mitigated)


def compare_patch_to_povs(oss_fuzz_project: OSSFuzzProject, patch_id: str):
    start_time = time.time()
    available_povs: list[analysis_graph_patches.PoVReportNode] = analysis_graph_patches.PoVReportNode.nodes.filter(pdt_project_id=oss_fuzz_project.project_id).all()
    logger.info("Time taken to get available PoVs: %s seconds", time.time() - start_time)

    start_time = time.time()
    for _ in range(3):
        patch_node: analysis_graph_patches.GeneratedPatch = analysis_graph_patches.GeneratedPatch.nodes.get_or_none(patch_key=patch_id, pdt_project_id=oss_fuzz_project.project_id)
        if patch_node:
            break
        logger.info("Patch %s not found in graph, waiting 30 seconds and retrying...", patch_id)
        time.sleep(30)
    else:
        raise ValueError(f"Patch {patch_id} not found in graph after 3 retries")

    assert oss_fuzz_project.pdclient is not None, "PDClient is not set"
    logger.info("Time taken to get patch node: %s seconds", time.time() - start_time)
    try:
        start_time = time.time()
        patch_artifacts_dir = get_patch_artifacts(patch_node.patch_key, patch_node.extra_metadata.get('build_request_id'), oss_fuzz_project.pdclient)
        logger.info("Time taken to get patch artifacts: %s seconds", time.time() - start_time)
    except Exception as e:
        logger.error("Error getting patch artifacts for %s: %s", patch_node.patch_key, e, exc_info=True)
        return

    try:
        shutil.copytree(patch_artifacts_dir, oss_fuzz_project.artifacts_dir, dirs_exist_ok=True, symlinks=True, ignore_dangling_symlinks=True)
    except FileNotFoundError as e:
        logger.error("Error copying patch artifacts for %s: %s", patch_node.patch_key, e, exc_info=True)
    except shutil.Error as e:
        logger.error("Error copying patch artifacts for %s: %s", patch_node.patch_key, e, exc_info=True)

    compare_time = time.time()
    total_success = 0
    total_errors = 0
    total_unknown = 0
    
    # Filter PoVs that belong to this project upfront
    max_workers = 3
    logger.info("Processing %d relevant PoVs with %d workers", len(available_povs), max_workers)
    
    # Prepare arguments as tuples (oss_fuzz_project, pov_report_node, patch_node)
    with tempfile.TemporaryDirectory() as harness_input_dir:
        task_args = []
        for pov in available_povs:
            if patch_node.mitigated_povs.is_connected(pov) or patch_node.non_mitigated_povs.is_connected(pov):
                continue
            harness_input = pov.harness_inputs.single()
            crashing_input = Path(harness_input_dir) / str(pov.key)
            crashing_input.write_bytes(bytes.fromhex(str(harness_input.content_hex)))
            args = (oss_fuzz_project, pov.key, patch_node.patch_key, crashing_input, pov.content.get('sanitizer'), pov.content.get('cp_harness_name'))
            task_args.append(args)
        
        with Pool(processes=max_workers) as pool:
            # Use imap_unordered since order doesn't matter
            result_iter = pool.imap_unordered(process_pov_report_wrapper, task_args)
            
            with alive_bar(len(available_povs), title='Comparing patch to PoVs (multiprocess)', bar='fish') as bar:
                for result in result_iter:
                    try:
                        pov_key, patch_key, was_mitigated = result
                        total_success += 1 if was_mitigated else 0
                        total_errors += 1 if was_mitigated is False else 0
                        total_unknown += 1 if was_mitigated is None else 0
                        if was_mitigated is None:
                            continue
                        pov = analysis_graph_patches.PoVReportNode.nodes.get_or_none(key=pov_key, pdt_project_id=oss_fuzz_project.project_id)
                        if was_mitigated:
                            if not patch_node.mitigated_povs.is_connected(pov):
                                patch_node.mitigated_povs.connect(pov)
                        else:
                            if not patch_node.non_mitigated_povs.is_connected(pov):
                                patch_node.non_mitigated_povs.connect(pov)
                        
                    except Exception as e:
                        logger.error("Error processing result: %s", e, exc_info=True)
                        total_errors += 1
                    
                    bar()
        
        logger.info("Time taken to compare patch to PoVs: %s seconds", time.time() - compare_time)
        logger.info("Total successes: %d, Total errors: %d, Total unknown: %d", total_success, total_errors, total_unknown)
        patch_node.finished_patch_patrol = True
        patch_node.save()

def main():
    args = get_args()

    with tempfile.TemporaryDirectory(dir=SHARED_ARTIFACTS_DIR) as tmp_dir:
        try:
            shutil.copytree(args.oss_fuzz_project_folder, tmp_dir, dirs_exist_ok=True, symlinks=True, ignore_dangling_symlinks=True)
        except FileNotFoundError as e:
            logger.error("Error copying OSS-Fuzz project folder for %s: %s", args.oss_fuzz_project_folder, e, exc_info=True)
        except shutil.Error as e:
            logger.error("Error copying OSS-Fuzz project folder for %s: %s", args.oss_fuzz_project_folder, e, exc_info=True)

        oss_fuzz_project = OSSFuzzProject(
            project_id=args.project_id,
            oss_fuzz_project_path=Path(tmp_dir),
            use_task_service=True
        )

        if args.mode == "patch":
            compare_patch_to_povs(oss_fuzz_project, args.patch_id)
        elif args.mode == "pov":
            compare_pov_to_patches(oss_fuzz_project, args.pov_report_id, args.crashing_input)


def get_args():
    parser = argparse.ArgumentParser()
    patch_group = parser.add_argument_group("patch mode")
    pov_group = parser.add_argument_group("pov mode")
    parser.add_argument("--project-id", type=str, help="The OSS-Fuzz project ID", required=True)
    parser.add_argument("--oss-fuzz-project-folder", type=Path, help="The OSS-Fuzz project repository", required=True)
    parser.add_argument("--mode", type=str, help="The mode to run in", required=True, choices=["patch", "pov"])

    pov_group.add_argument("--crashing-input", type=Path, help="The crashing input to use for the PoV report", required=False)
    pov_group.add_argument("--pov-report-id", type=str, help="The PoV report ID", required=False)

    patch_group.add_argument("--patch-id", type=str, help="The patch ID to compare to PoVs", required=False)
    return parser.parse_args()

if __name__ == "__main__":
    main()