import logging
import re

from agentlib import LocalObject, ObjectParser, Field, tools, LLMFunction
from agentlib.lib.agents import AgentWithHistory
from agentlib.lib.common.parsers import BaseParser
from langchain_core.output_parsers import PydanticOutputParser
from typing import Optional, Any, List, Dict


logger = logging.getLogger('SarifTriageGuy')
logger.setLevel(logging.INFO)

def get_report():
    pass

class MyParser(BaseParser):
    
    # Extra cost that we need to keep track when we do LLM calls
    llm_extra_calls_cost = 0

    # The model used to recover the format of the patch report
    recover_with = 'gpt-4o-mini'

    # This is the output format that describes the output of triageGuy
    __OUTPUT_DESCRIPTION = '/src/sarifguy/prompts/SarifTriageGuy/SarifTriageGuy.output.txt'

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.sarif_tg = kwargs.get('sarif_tg')

    def get_format_instructions(self) -> str:
        # This string is used in the user prompt as {{output_format}}
        output_format = open(self.__OUTPUT_DESCRIPTION, 'r').read()
        current_language = self.sarif_tg.LANGUAGE_EXPERTISE
        # Let's template the report example based on the current language
        patch_report_template = open(f'/src/sarifguy/prompts/SarifTriageGuy/extras-lang/reports/report.{current_language}', 'r').read()
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

        self.llm_extra_calls_cost += usage.get_costs(self.recover_with)['total_cost']

        return fixed_text

    def extract_summary_report(self, report:str) -> dict:
        # Extract the verdict and summary from the report
        verdict_match = re.search(r'<verdict>(.*?)</verdict>', report, re.DOTALL)
        if not verdict_match:
            raise Exception('Verdict not found in the report!')
        verdict = verdict_match.group(1).strip() if verdict_match else None

        summary_match = re.search(r'<summary>(.*?)</summary>', report, re.DOTALL)
        if not summary_match:
            raise Exception('Summary not found in the report!')
        summary = summary_match.group(1).strip() if summary_match else None

        sarif_tg_report = {
            "verdict": verdict,
            "summary": summary
        }

        return sarif_tg_report

    def parse(self, text: str):
        try_itr = 1
        while try_itr <= 3:
            m = re.search(r'<report>([\s\S]*?)</report>', text)
            if m:
                try:
                    summary_report = self.extract_summary_report(m.group(0))
                    logger.info(f'✅ Regexp-Parser: Successfully parsed the sarif_tg report from the output!')
                    return summary_report
                except Exception as e:
                    logger.info(f'🤡 Regexp-Error: Error parsing the sarif_tg report - {e}')
                    logger.info(f'🤡 Regexp-Error: Trying to fix the format of the sarif_tg report... Attempt {try_itr}!')
                    text = self.fix_format(text)
            else:
                # Technically, this should never happen
                # the parser should make sure that the output is always in the format.
                logger.info(f'🤡 Regexp-Error: Could not parse the sarif_tg report from the ouput!')
                logger.info(f'🤡 Regexp-Error: Trying to fix the format of the sarif_tg report... Attempt {try_itr}!')
                text = self.fix_format(text)
            try_itr+=1

class SarifTriageGuy(AgentWithHistory[dict,str]):

    # Choose a language model to use (default gpt-4-turbo)
    # __LLM_MODEL__ = 'o1-preview'
    # __LLM_MODEL__ = 'gpt-4o'
    # __LLM_MODEL__ = 'gpt-4o'
    __LLM_MODEL__ = "claude-3.5-sonnet"
    __OUTPUT_PARSER__ = MyParser
    __MAX_TOOL_ITERATIONS__ = 30

    __SYSTEM_PROMPT_TEMPLATE__ = '/src/sarifguy/prompts/SarifTriageGuy/system.j2'
    __USER_PROMPT_TEMPLATE__ = '/src/sarifguy/prompts/SarifTriageGuy/user.j2'

    __RAISE_ON_BUDGET_EXCEPTION__ = True
    __RAISE_ON_RATE_LIMIT_EXCEPTION__ = True

    LANGUAGE_EXPERTISE: Optional[str]
    PROJECT_NAME: Optional[str]
    RULE_ID: Optional[str]
    HAS_SARIF_MESSAGE: Optional[bool] = False
    SARIF_MESSAGE: Optional[str]
    LOCS_IN_SCOPE: Optional[str]
    HAS_DATA_FLOWS: Optional[bool] = False
    DATA_FLOWS: Optional[str]


    __LOGGER__ = logging.getLogger('SarifTriageGuy')
    __LOGGER__.setLevel(logging.ERROR)

    MAX_DATAFLOWS = 5

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        self.sarifguy_mode = kwargs.get('sarifguy_mode', None)

        self.LANGUAGE_EXPERTISE = kwargs.get('language')
        self.PROJECT_NAME = kwargs.get('project_name')
        self.RULE_ID = kwargs.get('rule_id')
        self.SARIF_MESSAGE = kwargs.get('sarif_message', None)
        self.DATA_FLOWS = kwargs.get('data_flows')

        if self.SARIF_MESSAGE == '':
            self.HAS_SARIF_MESSAGE = False
        else:
            self.HAS_SARIF_MESSAGE = True

        # Process the loc in scope and template the variable
        if kwargs.get('sarifguy_mode') == 'reasonable':
            locs_in_scope = kwargs.get('locs_in_scope')
            _locs_in_scope_ = ""
            for loc in locs_in_scope:
                _locs_in_scope_ += f"- File: {loc.file} | Function: {loc.func} | Start Line: {loc.line}\n"
            self.LOCS_IN_SCOPE = _locs_in_scope_
        else:
            locs_in_scope = kwargs.get('locs_in_scope')
            _locs_in_scope_ = ""
            for loc in locs_in_scope:
                _locs_in_scope_ += f"- File: {loc.file} | Start Line: {loc.line}\n"
            self.LOCS_IN_SCOPE = _locs_in_scope_

        if len(self.DATA_FLOWS) == 0:
            self.HAS_DATA_FLOWS = False
        else:
            self.HAS_DATA_FLOWS = True
            sarif_code_flows = kwargs.get('data_flows', None)
            
            assert(sarif_code_flows is not None), "Data flows should be provided if has_data_flows is True"
            
            # Limit the dataflows we are copy-pasting in the prompt
            if len(sarif_code_flows) > self.MAX_DATAFLOWS:
                sarif_code_flows = sarif_code_flows[:self.MAX_DATAFLOWS]

            # Extracting data flows!
            if kwargs.get('sarifguy_mode') == 'reasonable':
                _data_flows_ = ""
                for sarif_code_flow in sarif_code_flows:
                    _data_flows_ += f"- Dataflow ID: {sarif_code_flow.code_flow_id}\n"
                    for sarif_code_flow_loc in sarif_code_flow.locations:
                        _data_flows_ += f"  - File: {sarif_code_flow_loc.file} | Function: {sarif_code_flow_loc.func} | Start Line: {sarif_code_flow_loc.line}\n"
            else:
                _data_flows_ = ""
                for sarif_code_flow in sarif_code_flows:
                    _data_flows_ += f"- Dataflow ID: {sarif_code_flow.code_flow_id}\n"
                    for sarif_code_flow_loc in sarif_code_flow.locations:
                        _data_flows_ += f"  - File: {sarif_code_flow_loc.file} | Start Line: {sarif_code_flow_loc.line}\n"
            
            self.DATA_FLOWS = _data_flows_

    def get_input_vars(self, *args, **kw):
        vars = super().get_input_vars(*args, **kw)
        vars.update(
            LANGUAGE_EXPERTISE=self.LANGUAGE_EXPERTISE,
            PROJECT_NAME=self.PROJECT_NAME,
            HAS_SARIF_MESSAGE=self.HAS_SARIF_MESSAGE,
            SARIF_MESSAGE=self.SARIF_MESSAGE,
            LOCS_IN_SCOPE=self.LOCS_IN_SCOPE,
            RULE_ID=self.RULE_ID,
            HAS_DATA_FLOWS=self.HAS_DATA_FLOWS,
            DATA_FLOWS=self.DATA_FLOWS
        )
        return vars
    
    def get_cost(self, *args, **kw) -> float:
        total_cost = 0
        # We have to sum up all the costs of the LLM used by the agent
        for model_name, token_usage in self.token_usage.items():
            total_cost += token_usage.get_costs(model_name)['total_cost']
        return total_cost
    
    def get_available_tools(self): 
        if self.sarifguy_mode == "dumb":
            from ..toolbox.peek_src_dumb import show_file_at
            return [
                show_file_at
            ]
        else:
            from ..toolbox.peek_src import show_file_at, get_functions_by_file

            return [
                get_functions_by_file,
                show_file_at
            ]

    def get_output_parser(self):
        return MyParser(sarif_tg=self)