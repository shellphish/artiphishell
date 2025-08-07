#!/usr/bin/python3
from typing import Tuple, Optional, List
from pathlib import Path
import os
import logging

from patchery.data import ProgramInfo, ProgramPOI
from patchery.code_parsing.code_parser import CodeParser
from patchery.utils import WorkDirContext

_l = logging.getLogger(__name__)

from agentlib import (
    PlanExecutor,
    AgentPlan,
    AgentPlanStep,
    AgentPlanStepAttempt,
)

alib_logger = logging.getLogger("agentlib")
alib_logger.setLevel(logging.WARNING)


# Function to extract key_index values from pois.source_location
def extract_key_index_from_pois(data):
    key_indices = []
    line_numbers = []
    pois = data.get("pois", [])
    for poi in pois:
        source_location = poi.get("source_location", {})
        key_index = source_location.get("key_index")
        line_number = source_location.get("line_number")
        if key_index is not None:
            key_indices.append(key_index)
        if line_number is not None:
            line_numbers.append(line_number)
    return key_indices, line_numbers


# @tools.tool
# def read_report() -> str:
#     """
#     This function will read report.
#     """
#     return f'{VULN_REPORT}'


def read_code(pois: List[ProgramPOI], prog_info: ProgramInfo) -> str:
    """
    This function will read code.
    """
    prompts = ""
    for poi in pois:
        prompt = ""
        if not poi.func_src:
            funcparse = CodeParser(poi.file, lang=prog_info.lang)
            funcparse.parse()
            if poi.function in funcparse.functions:
                func = funcparse.functions[poi.function]
                start_line = func.start_line
                source_code = funcparse.func_code(poi.function)
                prompt = f"This function starts at line {start_line}\n" f"```\n{source_code}\n```\n"
        else:
            start_line = poi.func_startline
            source_code = poi.func_src
            prompt = f"This function starts at line {start_line}\n" f"```\n{source_code}\n```\n"
        prompts += prompt
    return f"{prompts}"


def read_suspected_lines(pois: List[ProgramPOI]) -> str:
    """Read the exact line of code in each function that are located on a trace when program crash is triggered"""
    # report = VULN_REPORT
    # if "ERROR: AddressSanitizer" in report:
    #     report_analyzer = ReportAnalyzer(report, ReportType.ASAN)
    #     poi_report = report_analyzer.analyze()
    lines_of_codes = ""
    for poi in pois:
        lines_of_codes += (
            f"The exact crash line of function {poi.function} is at line {poi.lineno} of the file:\n"
            f"{poi.linetext}\n"
        )
    return lines_of_codes

    # _, line_numbers = extract_key_index_from_pois(report)

    # ind = 0
    # lines_of_codes = ""
    # poi = POI
    # with open(poi.file, "r") as f:
    #     codes = f.read().replace("\\n", "\n")
    #     lines_of_codes += codes.split("\n")[line_numbers[ind]-1] + "\n"
    # ind += 1
    # return f"{lines_of_codes}"


# Code updater agent
def vuln_report_analyzer_agent(
    pois: List[ProgramPOI],
    prog_info: ProgramInfo,
    source_codes: str,
    suspected_lines: str,
) -> Tuple[str, int, int]:
    model = "gpt-4-turbo"

    PLAN = AgentPlan(
        steps=[
            AgentPlanStep(
                llm_model=model,
                name="read_source_code",
                description="Read the source code of the pois (points of interests) that are located on a stack trace when a program crash happens.",
            ),
            AgentPlanStep(
                llm_model=model,
                name="summarize_function",
                description="Given the source codes the function, please summarize each function. And if multiple functions are provide, summarize the call relationship among the functions you are provided",
            ),
            AgentPlanStep(
                llm_model=model,
                name="read_line_of_codes",
                description="Read the exact line of codes that are called in each function when a program crash happens",
            ),
            AgentPlanStep(
                llm_model=model,
                name="analyze_function",
                description="""
            Analyze the functions and pay attention to the codes around those suspected lines of code, 
            because those line of codes are on the stack trace of a program crash.
            Please summarize the vulnerability by providing all vulnerable functions and reasons why you think it is a vulnerability.
            If you identify multiple vulnerable functions, please summarize their relationships by providing a call chain to trigger the vulnerability.
            """,
            ),
            AgentPlanStep(
                llm_model=model,
                name="pinpoit_poi",
                description="""
            Analyze the functions and pay attention to the codes around those suspected lines of code, 
            because those line of codes are on the stack trace of a program crash.
            Please summarize the vulnerability by providing all vulnerable functions and reasons why you think it is a vulnerability.
            If you identify multiple vulnerable functions, please summarize their relationships by providing a call chain to trigger the vulnerability.
            Please only indicate vulnerability-related information.
            """,
            ),
        ]
    )

    agent_path = "/tmp/vuln_report_analyzer.json"
    # plan = PLAN.save_copy()
    if os.path.exists(agent_path):
        os.remove(agent_path)

    agent: VulnReportAnalyzer = VulnReportAnalyzer.reload_id_from_file_or_new(
        agent_path,
        plan=PLAN,
        goal="Analyze and summarize the vulnerability report",
        pois=pois,
        prog_info=prog_info,
        source_codes=source_codes,
        suspected_lines=suspected_lines,
    )

    agent.plan.sync_steps(PLAN.steps)
    agent.use_web_logging_config(clear=True)
    agent.warn(f"========== Agents plan ==========\n")
    agent.warn(f"========== Running agent ==========\n")
    result = agent.invoke()
    # FIXME: do not use hardcoded model name
    prompt_tokens = agent.token_usage["gpt-4-turbo-2024-04-09"].prompt_tokens
    completion_tokens = agent.token_usage["gpt-4-turbo-2024-04-09"].completion_tokens
    return result, prompt_tokens, completion_tokens


class VulnReportAnalyzer(PlanExecutor[str, str]):
    """
    This agent will follow the steps above.
    """

    # __SYSTEM_PROMPT_TEMPLATE__ = 'analyzer.system.j2'
    __SYSTEM_PROMPT_TEMPLATE__ = "analyzer.noreport.j2"
    __USER_PROMPT_TEMPLATE__ = "analyzer.user.j2"
    __LOGGER__ = logging.getLogger('VulnReportAnalyzer')
    __LOGGER__.setLevel('WARNING')

    report: Optional[str]
    pois: List[ProgramPOI]
    prog_info: ProgramInfo
    source_codes: str
    suspected_lines: str

    # def extract_step_attempt_context(
    #     self,
    #     step: AgentPlanStep,
    #     result: AgentResponse
    # ) -> str:
    #     """
    #     Due to the size of the code, rather than performing a summarization
    #     we just return the last successful llm output
    #     """
    #     return step.attempts[-1].result

    # def extract_final_results(self) -> str:
    #     """
    #     Due to the size of the code, rather than performing a summarization
    #     we just return the last successful llm output
    #     """
    #     steps = self.plan.get_past_steps()
    #     return steps[-1].attempts[-1].result

    def get_step_input_vars(self, step: AgentPlanStep) -> dict:
        return dict(
            **super().get_step_input_vars(step),
            source_codes=self.source_codes,
            suspected_lines=self.suspected_lines,
        )

    def process_step_result(self, step: AgentPlanStep, attempt: AgentPlanStepAttempt):
        return super().process_step_result(step, attempt)

    def validate_step_result(self, step: AgentPlanStep, attempt: AgentPlanStepAttempt, result) -> bool:

        # if step.name == 'code_verification':
        #     assert isinstance(result, str), "No code returned by the agent"
        #     # TODO: verifcation goes here!

        return super().validate_step_result(step, attempt, result)


def analyze_backtrace_report(
    pois: List[ProgramPOI], prog_info: ProgramInfo
) -> Tuple[str, int, int]:
    # global PROGRAM_INFO, VULN_REPORT, POI
    # PROGRAM_INFO = prog_info
    # VULN_REPORT = report
    # POI = poi
    with WorkDirContext(os.path.dirname(__file__)):
        if len(pois) > 3:
            pois = pois[:3]
        source_codes = read_code(pois, prog_info)
        suspected_lines = read_suspected_lines(pois)
        # For now, we just do not provide raw report to backtrace analyzer, since we have not figured out when it is better to provide report
        res, prompt_tokens, completion_tokens = vuln_report_analyzer_agent(
            pois, prog_info, source_codes, suspected_lines
        )
        return res, prompt_tokens, completion_tokens
