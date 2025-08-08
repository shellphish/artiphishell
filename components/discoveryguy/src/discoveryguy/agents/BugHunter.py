import logging
import re

from agentlib import LocalObject, ObjectParser, Field, tools, LLMFunction
from agentlib.lib.agents import AgentWithHistory
from agentlib.lib.common.parsers import BaseParser
from langchain_core.output_parsers import PydanticOutputParser
from typing import Optional, Any, List, Dict

from ..toolbox.peek_src import get_functions_by_file, show_file_at


logger = logging.getLogger('BugHunter')
logger.setLevel(logging.INFO)

def get_report():
    pass

class MyParser(BaseParser):

    # The model used to recover the format of the patch report
    recover_with = 'gpt-4o-mini'

    # This is the output format that describes the output of triageGuy
    __OUTPUT_DESCRIPTION = '/src/discoveryguy/prompts/BugHunter/BugHunter.output.txt'

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.bug_hunter = kwargs.get('bug_hunter')

    def get_format_instructions(self) -> str:
        # This string is used in the user prompt as {{output_format}}
        output_format = open(self.__OUTPUT_DESCRIPTION, 'r').read()
        current_language = self.bug_hunter.LANGUAGE_EXPERTISE
        # Let's template the report example based on the current language
        patch_report_template = open(f'/src/discoveryguy/prompts/BugHunter/extras-lang/warning_reports/report.{current_language}', 'r').read()
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

    def extract_bug_report(self, report:str) -> dict:
        # Extract the description
        description_match = re.search(r'<description>(.*?)</description>', report, re.DOTALL)
        if not description_match:
            raise Exception('Description not found in the report!')
        description = description_match.group(1).strip() if description_match else None

        # Extract the <verdict> element
        verdict = re.search(r'<verdict>(.*?)</verdict>', report, re.DOTALL)
        if not verdict:
            raise Exception('No verdict found in the report!')
        verdict = verdict.group(1).strip() if verdict else None

        # Extract the <exploit_plan> element
        exploit_plan = re.search(r'<exploit_plan>(.*?)</exploit_plan>', report, re.DOTALL)
        if not exploit_plan:
            raise Exception('No changes found in the report!')
        exploit_plan = exploit_plan.group(1).strip() if exploit_plan else None

        # Combine everything into a final dictionary
        bug_hunter_report = {
            "verdict": verdict,
            "description": description,
            "exploit_plan": exploit_plan
        }

        return bug_hunter_report

    def parse(self, text: str):
        try_itr = 1
        while try_itr <= 3:
            m = re.search(r'<report>([\s\S]*?)</report>', text)
            if m:
                try:
                    root_cause = self.extract_bug_report(m.group(0))
                    logger.info(f'✅ Regexp-Parser: Successfully parsed the bug hunter report from the output!')
                    return root_cause
                except Exception as e:
                    logger.info(f'🤡 Regexp-Error: Error parsing the bug hunter report - {e}')
                    logger.info(f'🤡 Regexp-Error: Trying to fix the format of the bug hunter report... Attempt {try_itr}!')
                    text = self.fix_format(text)
            else:
                # Technically, this should never happen
                # the parser should make sure that the output is always in the format.
                logger.info(f'🤡 Regexp-Error: Could not parse the bug hunter report from the ouput!')
                logger.info(f'🤡 Regexp-Error: Trying to fix the format of the bug hunter report... Attempt {try_itr}!')
                text = self.fix_format(text)
            try_itr+=1

class BugHunter(AgentWithHistory[dict,str]):

    # Choose a language model to use (default gpt-4-turbo)
    # __LLM_MODEL__ = 'o1-preview'
    # __LLM_MODEL__ = 'gpt-4o'
    #__LLM_MODEL__ = 'gpt-4o'
    __LLM_MODEL__ = "claude-3.5-sonnet"
    __OUTPUT_PARSER__ = MyParser
    __MAX_TOOL_ITERATIONS__ = 30

    __SYSTEM_PROMPT_TEMPLATE__ = '/src/discoveryguy/prompts/BugHunter/system.j2'
    __USER_PROMPT_TEMPLATE__ = '/src/discoveryguy/prompts/BugHunter/user.j2'

    LANGUAGE_EXPERTISE: Optional[str]
    PROJECT_NAME: Optional[str]
    VULN_FUNCTION: Optional[str]
    POI_HITS: Optional[str] = None
    RUN_ID: Optional[str]

    __LOGGER__ = logging.getLogger('BugHunter')
    __LOGGER__.setLevel(logging.ERROR)
        

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.LANGUAGE_EXPERTISE = kwargs.get('language')
        self.PROJECT_NAME = kwargs.get('project_name')
        self.VULN_FUNCTION = kwargs.get('vuln_function')
        self.POI_HITS = kwargs.get('poi_hits')
        self.RUN_ID = kwargs.get('run_id')

    def get_input_vars(self, *args, **kw):
        vars = super().get_input_vars(*args, **kw)
        vars.update(
            LANGUAGE_EXPERTISE=self.LANGUAGE_EXPERTISE,
            PROJECT_NAME=self.PROJECT_NAME,
            VULN_FUNCTION=self.VULN_FUNCTION,
            POI_HITS=self.POI_HITS,
            RUN_ID=self.RUN_ID
        )
        return vars
    
    def get_available_tools(self): 
        return [
            get_functions_by_file, show_file_at
        ]

    def get_output_parser(self):
        return MyParser(bug_hunter=self)