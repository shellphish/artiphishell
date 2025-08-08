

import logging
import re
from agentlib import LocalObject, ObjectParser, Field, tools, LLMFunction
from agentlib import AgentWithHistory, LocalObject, ObjectParser, Field, tools
from agentlib.lib.common.parsers import BaseParser

from ..toolbox.peek_src import get_functions_by_file, show_file_at
from typing import Optional, Any

logger = logging.getLogger('DebuggerGuy')

def get_script():
    pass


class MyParser(BaseParser):
    
    # Extra cost that we need to keep track when we do LLM calls
    llm_extra_calls_cost = 0

    # The model used to recover the format of the patch report
    recover_with = 'gpt-4o-mini'

    # This is the output format that describes the output of triageGuy
    __OUTPUT_DESCRIPTION = '/src/discoveryguy/prompts/DebuggerGuy/DebuggerGuy.output.txt'

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.debugger_guy = kwargs.get('debugger_guy')

    def get_format_instructions(self) -> str:
        # This string is used in the user prompt as {{output_format}}
        output_format = open(self.__OUTPUT_DESCRIPTION, 'r').read()
        current_language = self.debugger_guy.LANGUAGE_EXPERTISE
        # Let's template the report example based on the current language
        patch_report_template = open(f'/src/discoveryguy/prompts/DebuggerGuy/extras-lang/exploits_reports/report.{current_language}', 'r').read()
        output_format = output_format.replace('<PLACEHOLDER_FOR_EXAMPLE_REPORTS_BY_LANGUAGE>', patch_report_template)
        return output_format

    def invoke(self, msg, *args, **kwargs) -> dict:
        return self.parse(msg['output'])
    
    def fix_format(self, text: str) -> str:
        fix_llm = LLMFunction.create(
            'Fix the format of the current report according to the format instructions.\n\n# CURRENT REPORT\n{{ info.current_report }}\n\n# OUTPUT FORMAT\n{{ info.output_format }}',
            model=self.recover_with,
            use_loggers=True,
            temperature=0.0,
            include_usage=True
        )
        fixed_text, usage = fix_llm(
            info = dict(
                current_report = text,
                output_format = self.get_format_instructions()
            )
        )

        return fixed_text

    def extract_summary_report(self, report:str) -> dict:
        summary = re.search(r'<summary>(.*?)</summary>', report, re.DOTALL)
        if not summary:
            raise Exception('No summary found in the report!')
        summary = summary.group(1).strip() if summary else None
        
        # Combine everything into a final dictionary
        report = {
            "summary": summary
        }

        return report

    def parse(self, text: str):
        try_itr = 1
        while try_itr <= 3:
            m = re.search(r'<report>([\s\S]*?)</report>', text)
            if m:
                try:
                    summary = self.extract_summary_report(m.group(0))
                    logger.info(f'✅ Regexp-Parser: Successfully parsed the summary from the output!')
                    return summary
                except Exception as e:
                    logger.info(f'🤡 Regexp-Error: Error parsing the report - {e}')
                    logger.info(f'🤡 Regexp-Error: Trying to fix the format of the report... Attempt {try_itr}!')
                    text = self.fix_format(text)
            else:
                # Technically, this should never happen
                # the parser should make sure that the output is always in the format.
                logger.info(f'🤡 Regexp-Error: Could not parse the report from the ouput!')
                logger.info(f'🤡 Regexp-Error: Trying to fix the format of the report... Attempt {try_itr}!')
                text = self.fix_format(text)
            try_itr+=1

class DebuggerGuy(AgentWithHistory[dict, str]):
    __LLM_ARGS__ = {"temperature": 0}

    # Choose a language model to use (default gpt-4-turbo)
    #_LLM_MODEL__ = 'gpt-o1'
    __LLM_MODEL__ = 'gpt-4o'
    #__LLM_MODEL__ = "claude-3.5-sonnet"
    #__LLM_MODEL__ = "claude-3.7-sonnet"
    # __LLM_MODEL__ = "claude-3-opus"
    # __LLM_MODEL__ = "oai-gpt-o3-mini"
    #__LLM_MODEL__ = "claude-3.7-sonnet"

    __SYSTEM_PROMPT_TEMPLATE__ = "/src/discoveryguy/prompts/DebuggerGuy/system.j2"
    
    __USER_PROMPT_TEMPLATE__ = "/src/discoveryguy/prompts/DebuggerGuy/user.j2"

    __OUTPUT_PARSER__ = MyParser
    __MAX_TOOL_ITERATIONS__ = 100

    # __OUTPUT_PARSER__ = ObjectParser(CrashingScript, use_fallback=True,  use_structured_output=True)

    LANGUAGE_EXPERTISE: Optional[str]
    PROJECT_NAME: Optional[str]
    REPORT: Optional[str]
    LOCS_IN_SCOPE: Optional[str]
    HARNESS_PATH: Optional[str]
    HARNESS_CODE: Optional[str]

    __LOGGER__ = logging.getLogger("DebuggerGuy")
    __LOGGER__.setLevel(logging.ERROR)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.LANGUAGE_EXPERTISE = kwargs.get("language")
        self.PROJECT_NAME = kwargs.get("project_name")
        self.VULN_NAME = kwargs.get("vuln_name")
        self.HARNESS_PATH = kwargs.get('harness_path')
        self.HARNESS_CODE = kwargs.get('harness_code')

        report = kwargs.get("report")

        exploit_script = report['exploit_script']
        input_path = report['input']
        vuln_desc = report['description']
        exploit_plan = report['exploit_plan']


        self.REPORT = "=== START REPORT ===\n"
        self.REPORT += f"VULNERABILITY DESCRIPTION: {vuln_desc}\n"
        self.REPORT += f"EXPLOIT PLAN: {exploit_plan}\n"
        locs_in_scope = kwargs.get('locs_in_scope')
        _locs_in_scope_ = ""
        for loc in locs_in_scope:
            _locs_in_scope_ += f"- File: {loc.file} | Function: {loc.func} | Start Line: {loc.line}\n"
        self.LOCS_IN_SCOPE = _locs_in_scope_
        self.REPORT += f"FAILING EXPLOIT SCRIPT: {exploit_script}\n"
        with open(input_path, 'r', encoding="latin-1") as f:
            input_data = f.read()
        self.REPORT += f"PAYLOAD GENERATED BY THE SCRIPT: {input_data}\n"
        self.REPORT += "=== END REPORT ===\n"

    def get_input_vars(self, *args, **kw):
        vars = super().get_input_vars(*args, **kw)
        vars.update(
            LANGUAGE_EXPERTISE=self.LANGUAGE_EXPERTISE,
            PROJECT_NAME=self.PROJECT_NAME,
            VULN_NAME=self.VULN_NAME,
            LOCS_IN_SCOPE=self.LOCS_IN_SCOPE,
            REPORT=self.REPORT,
            HARNESS_PATH=self.HARNESS_PATH,
            HARNESS_CODE=self.HARNESS_CODE
        )
        return vars

    def get_available_tools(self):
        
        ALL_TOOLS = {
            "get_functions_by_file": get_functions_by_file,
        }        

        return ALL_TOOLS.values()

        
    def increase_temperature_by(self, value: float):
        current_temperatue = self.__LLM_ARGS__.get('temperature', 0.0)
        print(f'🥶🥶🥶 DebuggerGuy is heating up... (OLD temperature: {current_temperatue}) 🥶🥶🥶')
        new_temperature = current_temperatue + value
        # The temperature should be between 0.0 and 1.0
        new_temperature = max(0.0, min(1.0, new_temperature))
        print(f'🔥🔥🔥 DebuggerGuy is heating up... (Current temperature: {new_temperature}) 🔥🔥🔥')
        # Update the temperature
        DebuggerGuy.__LLM_ARGS__ = {"temperature": new_temperature}

    def get_output_parser(self):
        return MyParser(debugger_guy=self)