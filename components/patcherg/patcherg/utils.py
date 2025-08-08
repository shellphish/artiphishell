from pathlib import Path

from shellphish_crs_utils.models import POIReport
from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject

QUERY_FOLDER = Path(__file__).parent / "queries"
SHARED_FOLDER = Path("/shared/patcherg")
def build_oss_project(local_run: bool, poi_report: POIReport, source_root: Path, target_root: Path, patch_diff: Path | None = None):
    oss_fuzz_project = OSSFuzzProject(
        project_id=poi_report.project_id,
        oss_fuzz_project_path=target_root,
        project_source=source_root,
        use_task_service=not local_run,
    )
    sanitizer_string = poi_report.sanitizer.value
    oss_fuzz_project.build_builder_image()
    oss_fuzz_project.build_runner_image()
    if patch_diff:
        build_result = oss_fuzz_project.build_target(
            patch_path=patch_diff, sanitizer=sanitizer_string, print_output=False
        )
    else:
        build_result = oss_fuzz_project.build_target(
            sanitizer=sanitizer_string, print_output=False
        )
    return build_result.build_success, oss_fuzz_project
