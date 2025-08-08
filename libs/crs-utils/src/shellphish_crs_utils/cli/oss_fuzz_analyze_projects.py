from collections import defaultdict
import os
import glob
from pathlib import Path
import sys

from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject
from crs_telemetry.utils import init_otel, get_otel_tracer

init_otel(os.environ.get("TASK_NAME", "oss_fuzz"), "static_analysis", "oss_fuzz.analyze_projects")
tracer = get_otel_tracer()

def main():
    # Here, we analyze the metadata of each project in the provided oss-fuzz dir to calculate statistics
    with tracer.start_as_current_span("oss_fuzz.analyze_projects") as span:
        import ipdb; ipdb.post_mortem()
        oss_fuzz_path = Path(sys.argv[1])
        projects_dir = oss_fuzz_path / 'projects'

        by_language = defaultdict(int)

        for i, project_path in enumerate(projects_dir.iterdir()):
            try:
                if not project_path.is_dir():
                    continue
                if not (project_path / 'Dockerfile').is_file():
                    continue

                project = OSSFuzzProject(project_path)

                by_language[project.project_metadata.language] += 1

                if i % 100 == 0:
                    print(f'Processed {i} projects:')
                    for language, count in by_language.items():
                        print(f'{language}: {count}')
                    print()
            except Exception as e:
                print(f'Error processing project {project_path}: {e}')
                raise

        print(f'Processed {i} projects:')
        for language, count in sorted(by_language.items(), key=lambda x: x[1], reverse=True):
            print(f'{language}: {count}')
            span.add_event("language_count", {"language": language, "count": count})