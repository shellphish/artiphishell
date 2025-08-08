import argparse
import yaml

from pathlib import Path

from shellphish_crs_utils.models.crs_reports import POIReport
from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject
from crs_telemetry.utils import (
    get_otel_tracer,
    init_otel,
    init_llm_otel,
)
from opentelemetry.trace import Status, StatusCode
from debug_lib.agent import run_agent

init_otel(
    name="dyva",
    crs_action_category="dynamic_analysis",
    crs_action_name="root_cause_analysis_with_llm_debugger",
)
init_llm_otel()

tracer = get_otel_tracer()


def get_args():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--oss-fuzz-project",
        type=Path,
        help="Path to the oss fuzz project",
        required=True,
    )
    parser.add_argument(
        "--crashing-input",
        type=Path,
        help="Path to the crashing input",
        required=True,
    )
    parser.add_argument(
        "--poi-report", required=True, type=Path, help="Path to poi report"
    )
    parser.add_argument(
        "--output-path", type=Path, help="Path to output_path", required=True
    )
    parser.add_argument(
        "--arbitrary-crash", action="store_true", help="Use arbitrary crash"
    )
    args = parser.parse_args()
    return args


def main():
    args = get_args()
    poi_report = POIReport.model_validate(yaml.safe_load(args.poi_report.read_text()))
    oss_fuzz_project = OSSFuzzProject(
        args.oss_fuzz_project, args.oss_fuzz_project / "artifacts" / "built_src"
    )

    with tracer.start_as_current_span("dyva_root_cause_analysis") as span:
        root_cause, _, _ = run_agent(
            oss_fuzz_project=oss_fuzz_project,
            poi_report=poi_report,
            crashing_input=args.crashing_input,
            output_path=args.output_path,
            arbitrary_crash=args.arbitrary_crash,
            max_iterations=50,
            model="gpt-4.1-mini"
        )
        span.add_event(
            "root_cause_analysis.result",
            attributes={
                "root_cause_analysis.result": yaml.dump(
                    root_cause.model_dump(mode="json")
                )
            },
        )
        span.set_status(Status(StatusCode.OK))


if __name__ == "__main__":
    main()
