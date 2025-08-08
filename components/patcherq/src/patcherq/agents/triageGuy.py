
import re
import logging

from agentlib import Agent, LLMFunction
from agentlib.lib.common.parsers import BaseParser
from typing import Optional, Any

from ..toolbox.peek_src import show_file_at, get_functions_by_file, search_string_in_file, search_function, get_function_or_struct_location
from ..toolbox.lang_server_ops import LANG_SERVER_TOOLS
from ..toolbox.code_ql_ops import CODEQL_TOOLS

from ..config import Config, CRSMode

from .exceptions import MaxToolCallsExceeded

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Define the tools that the agent can use
ALL_TOOLS = {
    'show_file_at': show_file_at,
    'get_functions_by_file': get_functions_by_file,
    'search_string_in_file': search_string_in_file,
    'get_function_or_struct_location': get_function_or_struct_location,
    # 'search_function': search_function,
    #'get_invariant_for': get_invariant_for
}

# This is the list of tools that the agent can use
# in case the invariants report is not available
TOOLS_NO_INVARIANTS = {
    'show_file_at': show_file_at,
    'get_functions_by_file': get_functions_by_file,
    'search_string_in_file': search_string_in_file,
    'get_function_or_struct_location': get_function_or_struct_location,
    #'get_struct_definition': get_struct_definition,
    #'get_function_callers': get_function_callers,
}

class MyParser(BaseParser):

    # The model used to recover the format of the patch report
    recover_with = 'gpt-4.1-mini'

    # This is the template used to recover the format of the root cause report if the parsing fails
    __ROOT_CAUSE_FORMAT_RECOVERY_TEMPLATE = '/src/patcherq/prompts/triageGuy/extras/root_cause_format_recovery.j2'

    # This is the output format that describes the output of triageGuy
    __OUTPUT_DESCRIPTION = '/src/patcherq/prompts/triageGuy/triageGuy.output.txt'

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.triage_guy = kwargs.get('triage_guy')

    def get_format_instructions(self) -> str:
        # This string is used in the user prompt as {{output_format}}
        output_format = open(self.__OUTPUT_DESCRIPTION, 'r').read()
        current_language = self.triage_guy.LANGUAGE_EXPERTISE
        # Let's template the report example based on the current language
        patch_report_template = open(f'/src/patcherq/prompts/triageGuy/extras-lang/rca_reports/report.{current_language}', 'r').read()
        output_format = output_format.replace('<PLACEHOLDER_FOR_EXAMPLE_REPORTS_BY_LANGUAGE>', patch_report_template)
        return output_format

    def invoke(self, msg, *args, **kwargs) -> dict:
        if msg['output'] == 'Agent stopped due to max iterations.':
            raise MaxToolCallsExceeded
        return self.parse(msg['output'])
    
    def fix_format(self, text: str) -> str:
        fix_llm = LLMFunction.create(
            'Fix the format of the current root cause report according to the format instructions.\n\n# CURRENT ROOT CAUSE REPORT\n{{ info.current_rc }}\n\n# OUTPUT FORMAT\n{{ info.output_format }}',
            model=self.recover_with,
            use_loggers=True,
            temperature=0.0,
            include_usage=True
        )
        fixed_text, usage = fix_llm(
            info = dict(
                current_rc = text,
                output_format = self.get_format_instructions()
            )
        )

        return fixed_text

    def extract_root_cause(self, report:str) -> dict:
        # Extract the description
        description_match = re.search(r'<description>(.*?)</description>', report, re.DOTALL)
        if not description_match:
            raise Exception('Description not found in the root cause report!')
        description = description_match.group(1).strip() if description_match else None

        # Extract all <change> elements
        changes = re.findall(r'<change>(.*?)</change>', report, re.DOTALL)
        if not changes:
            raise Exception('No changes found in the root cause report!')
        parsed_changes = []
        
        for change in changes:
            # Extract file path within each <change>
            file_match = re.search(r'<file>(.*?)</file>', change)
            if not file_match:
                raise Exception('File path not found in the change!')
            file_path = file_match.group(1).strip()
            
            # Extract all <fix> elements within each <change>
            fixes = re.findall(r'<fix>(.*?)</fix>', change, re.DOTALL)
            fix_list = [fix.strip() for fix in fixes]

            parsed_changes.append({
                "file": file_path,
                "fixes": fix_list
            })

        # Combine everything into a final dictionary
        root_cause_report = {
            "description": description,
            "changes": parsed_changes
        }

        return root_cause_report

    def parse(self, text: str):
        try_itr = 1
        while try_itr <= 3:
            m = re.search(r'<root_cause_report>([\s\S]*?)</root_cause_report>', text)
            if m:
                try:
                    root_cause = self.extract_root_cause(m.group(0))
                    logger.info('✅ Regexp-Parser: Successfully parsed the root cause report from the output!')
                    return root_cause
                except Exception as e:
                    logger.info('🤡 Regexp-Error: Error parsing the root cause report - %s', e)
                    logger.info('🤡 Regexp-Error: Trying to fix the format of the root cause report... Attempt %d!', try_itr)
                    text = self.fix_format(text)
            else:
                # Technically, this should never happen
                # the parser should make sure that the output is always in the format.
                #logger.info(f'🤡 Regexp-Error: Could not parse the root cause report from the ouput!')
                logger.info(' Detected invalid format of the root cause report, fixing... (attempt: %d)', try_itr)
                text = self.fix_format(text)
            try_itr+=1


class TriageGuy(Agent[dict,str]):
    __LLM_MODEL__ = 'gpt-4.1'
    #__LLM_MODEL__ = 'claude-3.5-sonnet'

    __SYSTEM_PROMPT_TEMPLATE__ = '/src/patcherq/prompts/triageGuy/triageGuy.CoT.system.j2' 
    __USER_PROMPT_TEMPLATE__ = '/src/patcherq/prompts/triageGuy/triageGuy.CoT.user.j2'
    __OUTPUT_PARSER__ = MyParser
    __MAX_TOOL_ITERATIONS__ = 75

    __RAISE_ON_BUDGET_EXCEPTION__ = True
    __RAISE_ON_RATE_LIMIT_EXCEPTION__ = True

    __LLM_ARGS__ = {
        'temperature': 0.0,
        'max_tokens': 8192
    }

    INITIAL_CONTEXT_REPORT: Optional[str]
    LANGUAGE_EXPERTISE: Optional[str]
    REFINE_THIS: Optional[str]
    FAILED_FUNCTIONALITY: Optional[str]

    # Extra state variables to configure the agent
    with_invariants = False
    with_lang_server = False
    with_codeql_server = False

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # ================
        # Prompt variables
        # ================
        self.INITIAL_CONTEXT_REPORT = kwargs.get('init_context')
        self.LANGUAGE_EXPERTISE = kwargs.get('project_language')
        self.REFINE_THIS = kwargs.get('refine_this', None)
        self.FAILED_FUNCTIONALITY = kwargs.get('failed_functionality', None)

        # NOTE: putting it to None so it doesn't show up in the prompt.
        if self.FAILED_FUNCTIONALITY == False:
            self.FAILED_FUNCTIONALITY = None
        
        # ================
        # State variables
        # ================
        # This is used to determine if the agent should use the invariants tool
        self.with_invariants = kwargs.get('with_invariants', False)
        self.with_codeql_server = kwargs.get('with_codeql_server', False)
        self.with_lang_server = kwargs.get('with_lang_server', False)
        

    def get_input_vars(self, *args, **kw):
        # Any returned dict will be use as an input to template the prompts
        # of this agent.
        vars = super().get_input_vars(*args, **kw)
        vars.update(
            INITIAL_CONTEXT_REPORT=self.INITIAL_CONTEXT_REPORT,
            LANGUAGE_EXPERTISE=self.LANGUAGE_EXPERTISE,
            REFINE_THIS=self.REFINE_THIS,
            FAILED_FUNCTIONALITY=self.FAILED_FUNCTIONALITY
        )
        return vars
    
    def get_available_tools(self):
        # TODO: maybe activate tools in a smarter way here...
        my_tools = []
        if self.with_invariants:
            my_tools.extend(ALL_TOOLS.values())
        else:
            my_tools.extend(TOOLS_NO_INVARIANTS.values())
        
        if self.with_lang_server:
            my_tools.extend(LANG_SERVER_TOOLS.values())
            
        if self.with_codeql_server:
            my_tools.extend(CODEQL_TOOLS.values())
  
        # if Config.crs_mode == CRSMode.DELTA and Config.use_diff_tool_for_delta:
        #     my_tools.extend([get_diff_snippet, list_changed_functions])
            
        return my_tools

    def increase_temperature_by(self, value: float):
        current_temperatue = self.__LLM_ARGS__.get('temperature', 0.0)
        new_temperature = current_temperatue + value
        # The temperature should be between 0.0 and 1.0
        new_temperature = max(0.0, min(1.0, new_temperature))
        logger.info('🔥🔥🔥 TriageGuy is heating up... (Current temperature: %s) 🔥🔥🔥', new_temperature)
        # Update the temperature
        TriageGuy.__LLM_ARGS__ = {"temperature": new_temperature}

    def reset_temperature(self):
        TriageGuy.__LLM_ARGS__ = {"temperature": 0.0}

    def get_output_parser(self):
        return MyParser(triage_guy=self)
