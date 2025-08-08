import yaml
import logging
import time
import shutil

from pathlib import Path

from rich.console import Console
from rich.logging import RichHandler

from shellphish_crs_utils.models import RootCauseReport, POIReport
from shellphish_crs_utils.utils import artiphishell_should_fail_on_error
from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject
from shellphish_crs_utils.function_resolver import FunctionResolver
from shellphish_crs_utils import LOG_FORMAT
from crs_telemetry.utils import get_otel_tracer, get_current_span

from debug_lib.agent.engine import tool_calls, utils, debug_helper
from debug_lib.agent.dyva_agent import DyvaAgent
from debug_lib.agent.investigator_agent import InvestigatorAgent
from debug_lib.agent.debug_agent import DebugAgent
from debug_lib.agent.critic_agent import CriticAgent


DYVA_AGENT_ART = r"""
    ______  ___    _____       ___   _____________   ________
   / __ \ \/ / |  / /   |     /   | / ____/ ____/ | / /_  __/
  / / / /\  /| | / / /| |    / /| |/ / __/ __/ /  |/ / / /
 / /_/ / / / | |/ / ___ |   / ___ / /_/ / /___/ /|  / / /
/_____/ /_/  |___/_/  |_|  /_/  |_\____/_____/_/ |_/ /_/
"""
log = logging.getLogger("dyva-runner")
tracer = get_otel_tracer()

def setup_global_state(crashing_input: Path,
                       oss_fuzz_project: OSSFuzzProject,
                       function_resolver: FunctionResolver = None,
                       poi_report: POIReport = None,
                       output_path: Path = None,
                       arbitrary_crash: bool = False):

    pov_input = oss_fuzz_project.artifacts_dir / "work" / "pov_input"
    shutil.copy(crashing_input, pov_input)
    # Path("/work").mkdir(parents=True, exist_ok=True)
    # shutil.copy(crashing_input, "/work/pov_input")

    debug_helper.init_dyva_state(
        oss_fuzz_project=oss_fuzz_project,
        input_data=pov_input,
        function_resolver=function_resolver,
        cp_name=poi_report.project_name,
        project_id=poi_report.project_id,
        poi_report=poi_report,
        output_path=output_path,
        arbitrary_crash=arbitrary_crash,
    )

def three_agent_strategy():
    total_cost = 0
    with tracer.start_as_current_span("dyva_agent.investigate") as span:
        investigator = InvestigatorAgent()
        resp = investigator.invoke()
        investigation_plan = resp.value.split("```yaml")[1].split("```")[0]
        span.set_attribute("crs.action.gen_ai.id", resp.get_id())
        total_cost += sum(
            (usage.get_costs(model)["total_cost"] for model, usage in investigator.token_usage.items())
        )
    critic_agent = CriticAgent()
    for i in range(3):
        if resp.value is None:
            log.error("Investigator agent failed to find root cause")
            break
        with tracer.start_as_current_span("dyva_agent.debug_execute") as span:
            debug_agent = DebugAgent()
            resp = debug_agent.invoke({"investigation_plan": investigation_plan})
            observation_summary = resp.value.split("```yaml")[1].split("```")[0]
            span.set_attribute("crs.action.gen_ai.id", resp.get_id())
            total_cost += sum(
                (usage.get_costs(model)["total_cost"] for model, usage in debug_agent.token_usage.items())
            )

        with tracer.start_as_current_span("dyva_agent.critic") as span:
            resp = critic_agent.invoke({"observation_summary": observation_summary})
            if debug_helper.DYVA_STATE.found_root_cause:
                break
            investigation_plan = resp.value.split("```yaml")[1].split("```")[0]
            span.set_attribute("crs.action.gen_ai.id", resp.get_id())
            total_cost += sum(
                (usage.get_costs(model)["total_cost"] for model, usage in critic_agent.token_usage.items())
            )
    print(f"Total cost of three agent strategy: ${total_cost:.2f}")

def single_agent_strategy(model: str = "gpt-4.1-mini", max_iterations: int = 15) -> tuple[list, float]:
    total_cost = 0
    with tracer.start_as_current_span("dyva_agent.single_agent_strategy") as span:
        dyva_agent = DyvaAgent(model=model, max_iterations=max_iterations)

        try:
            while not debug_helper.DYVA_STATE.found_root_cause or len(dyva_agent.tools_used) < 2:
                if dyva_agent.iterations_left <= 0:
                    break
                with tracer.start_as_current_span("dyva_agent.invoke"):
                    # TODO: Add retry logic if the agent fails due to rate limiting or other issues
                    try:
                        response = dyva_agent.invoke(
                            {
                                "retry": True if dyva_agent.iterations_left < max_iterations else False,
                                "root_cause": None,
                                "file_contents": None,
                            }
                        )
                    except Exception as e:
                        log.error("Error invoking DyvaAgent: %s", e, exc_info=True)
                        time.sleep(10)  # Wait before retrying
                        continue
                    span.set_attribute("crs.action.gen_ai.id", response.get_id())

                total_cost += sum(
                    (usage.get_costs(model)["total_cost"] for model, usage in dyva_agent.token_usage.items())
                )
        except Exception as e:
            log.exception("Error during single agent strategy: %s", e, exc_info=True)
    print(f"Total cost of single agent strategy: ${total_cost:.2f}")
    return dyva_agent.tool_history, total_cost

def run_agent(
    oss_fuzz_project: OSSFuzzProject,
    poi_report: POIReport,
    crashing_input: Path,
    output_path: Path = None,
    arbitrary_crash: bool = False,
    max_iterations: int = 30,
    model: str = "gpt-4.1-mini"
) -> tuple[RootCauseReport, list, float]:
    """
    WARNING oss_fuzz_project WILL BE MOUNTED IN A DOCKER CONTAINER, ENSURE IT IS IN /shared
    :param oss_fuzz_project: Path to the oss fuzz project
    :param poi_report: Path to poi report
    :param crashing_input: Path to the crashing input
    :param function_indices: Path to the function indices
    :param function_json: Path to the function JSON dirs
    :param output_path: Path where root cause report will be written
    :param arbitrary_crash: Run dyva on the current crash not the PoI Report crash
    :param max_iterations: Maximum number of iterations to run dyva

    """

    print(DYVA_AGENT_ART)

    cost = 0
    tools_used = []

    try:
        assert oss_fuzz_project.project_source is not None, "Source repo path is not set"
        assert str(oss_fuzz_project.artifacts_dir).startswith("/shared"), (
            f"Artifacts dir is not in /shared: {oss_fuzz_project.artifacts_dir}"
        )
        
        span = get_current_span()
        span.set_attribute("crs.action.target.harness", poi_report.cp_harness_name)

        setup_global_state(crashing_input=crashing_input,
                           oss_fuzz_project=oss_fuzz_project,
                           poi_report=poi_report,
                           output_path=output_path,
                           arbitrary_crash=arbitrary_crash)

        port_dir = Path("/shared/debug_lib/port/")
        if False:
            # tool_calls.get_function_source(**{'function_signature': 'int ngx_http_process_white_list(ngx_http_request_t *, ngx_table_elt_t *, int)', 'file_path': '/src/nginx/src/http/ngx_http_request.c', 'reference_line_number': 3912})
            # tool_calls.get_context_at_lines(**{'lines': [43, 44, 45, 46, 47], 'src_file': 'project-parent/fuzz-targets/src/main/java/com/example/TikaAppUntarringFuzzer.java', 'classpath': 'org.apache.tika.cli'})
            # tool_calls.set_breakpoint_and_get_context(**{'function_signature': 'ngx_http_auth_basic_user(ngx_http_request_t *r)', 'src_file': '/src/nginx/src/http/ngx_http_core_module.c', 'line_number': 1994})
            debug_helper.DYVA_STATE.class_name = "com.example.TikaAppUntarringFuzzer"
            with utils.build_debug_and_run_image(port_dir) as background_runner:
                tool_calls.get_context_at_lines(**{'lines': [43, 44, 45, 46, 47], 'src_file': 'project-parent/fuzz-targets/src/main/java/com/example/TikaAppUntarringFuzzer.java', 'classpath': 'com.example.TikaAppUntarringFuzzer'})
        else:
            with utils.build_debug_and_run_image(port_dir) as background_runner:

                try:
                    crash_report = utils.crash_report_from_dyva_state()
                except Exception as e:
                    log.error("Error getting crash report: %s", e, exc_info=True)
                    raise e
                log.info("Crash Report: %s", crash_report)
                # three_agent_strategy()
                tools_used, cost = single_agent_strategy(model=model, max_iterations=max_iterations)
    except Exception as e:
        log.error("Unexpected error: %s", e, exc_info=True)
        if artiphishell_should_fail_on_error():
            raise e

    if not debug_helper.DYVA_STATE.found_root_cause:
        # Root cause not found
        root_cause = RootCauseReport(
            found_root_cause=False,
            errored=True,
            dataflow="",
            description="No root cause found",
            bug_locations=[],
            bug_classes=[],
            patches=[],
            root_cause_locations=[],
        )

        log.error("Failed to find root cause")
        with output_path.open("w") as f:
            yaml.dump(root_cause.model_dump(), f)
    else:
        log.info("Root cause found")
        root_cause = debug_helper.DYVA_STATE.root_cause_report

    return root_cause, tools_used, cost
