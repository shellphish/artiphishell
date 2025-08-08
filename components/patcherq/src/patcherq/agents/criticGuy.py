import re
import logging

from agentlib import Agent, LLMFunction
from agentlib.lib.common.parsers import BaseParser
from typing import Optional, Any

# from ..toolbox.peek_src import show_file_at, get_functions_by_file, search_string_in_file, search_function, get_function_or_struct_location
# from ..toolbox.lang_server_ops import LANG_SERVER_TOOLS
# from ..toolbox.code_ql_ops import CODEQL_TOOLS
# from ..toolbox.peek_diff import get_diff_snippet

# from ..config import Config, CRSMode

# from .exceptions import MaxToolCallsExceeded

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Define the tools that the agent can use
# ALL_TOOLS = {
#     'show_file_at': show_file_at,
#     'get_functions_by_file': get_functions_by_file,
#     'search_string_in_file': search_string_in_file,
#     'get_function_or_struct_location': get_function_or_struct_location,
# }


class MyParser(BaseParser):

    # The model used to recover the format of the patch report
    recover_with = 'gpt-4.1-mini'

    # This is the output format that describes the output of criticGuy
    __OUTPUT_DESCRIPTION = '/src/patcherq/prompts/criticGuy/criticGuy.output.txt'

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.critic_guy = kwargs.get('critic_guy')

    def get_format_instructions(self) -> str:
        # This string is used in the user prompt as {{output_format}}
        output_format = open(self.__OUTPUT_DESCRIPTION, 'r').read()
        return output_format

    def invoke(self, msg, *args, **kwargs) -> dict:
        # if msg['output'] == 'Agent stopped due to max iterations.':
        #     raise MaxToolCallsExceeded
        # return self.parse(msg['output'])
        return self.parse(msg.content)
    
    def fix_format(self, text: str) -> str:
        fix_llm = LLMFunction.create(
            'Fix the format of the current feedback report according to the format instructions.\n\n# CURRENT feedback REPORT\n{{ info.current_rc }}\n\n# OUTPUT FORMAT\n{{ info.output_format }}',
            model=self.recover_with,
            use_loggers=True,
            temperature=0.0,
            include_usage=True
        )
        fixed_text, _ = fix_llm(
            info = dict(
                current_rc = text,
                output_format = self.get_format_instructions()
            )
        )

        return fixed_text

    def extract_feedback(self, report:str) -> dict:
        # Extract the analysis
        analysis_match = re.search(r'<analysis>(.*?)</analysis>', report, re.DOTALL)
        if not analysis_match:
            raise Exception('analysis not found in the feedback report!')
        analysis = analysis_match.group(1).strip() if analysis_match else None

        # Extract the verdict
        verdict_match =  re.search(r'<verdict>(.*?)</verdict>', report, re.DOTALL)
        if not verdict_match:
            raise Exception('Verdict not found in the feedback report!')
        verdict = verdict_match.group(1).strip() if verdict_match else None

        # Extract the feedback
        feedback_match = re.search(r'<feedback>(.*?)</feedback>', report, re.DOTALL)
        if not feedback_match:
            raise Exception('Feedback not found in the feedback report!')
        feedback = feedback_match.group(1).strip() if feedback_match else None

        # Combine everything into a final dictionary
        feedback_report = {
            "analysis": analysis,
            "verdict": verdict,
            "feedback": feedback
        }

        return feedback_report

    def parse(self, text: str):
        try_itr = 1
        while try_itr <= 3:
            m = re.search(r'<feedback_report>([\s\S]*?)</feedback_report>', text)
            if m:
                try:
                    feedback = self.extract_feedback(m.group(0))
                    logger.info('✅ Regexp-Parser: Successfully parsed the feedback report from the output!')
                    return feedback
                except Exception as e:
                    logger.info('🤡 Regexp-Error: Error parsing the feedback report - %s', e)
                    logger.info('🤡 Regexp-Error: Trying to fix the format of the feedback report... Attempt %d!', try_itr)
                    text = self.fix_format(text)
            else:
                # Technically, this should never happen
                # the parser should make sure that the output is always in the format.
                #logger.info(f'🤡 Regexp-Error: Could not parse the feedback report from the ouput!')
                logger.info(' Detected invalid format of the feedback report, fixing... (attempt: %d)', try_itr)
                text = self.fix_format(text)
            try_itr+=1


class CriticGuy(Agent[dict,str]):
    __LLM_MODEL__ = 'o3'
    #__LLM_MODEL__ = 'claude-3.5-sonnet'

    __SYSTEM_PROMPT_TEMPLATE__ = '/src/patcherq/prompts/criticGuy/criticGuy.system.j2' 
    __USER_PROMPT_TEMPLATE__ = '/src/patcherq/prompts/criticGuy/criticGuy.user.j2'
    __OUTPUT_PARSER__ = MyParser
    # __MAX_TOOL_ITERATIONS__ = 30
    # __MAX_TOOL_ITERATIONS__ = 50

    __RAISE_ON_BUDGET_EXCEPTION__ = True

    __LLM_ARGS__ = {"temperature": 0.0}

    PROJECT_NAME: Optional[str]
    PROJECT_LANGUAGE: Optional[str]
    PATCH: Optional[str]
    ROOT_CAUSE_REPORT: Optional[str]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # ================
        # Prompt variables
        # ================
        self.PROJECT_NAME = kwargs.get('project_name')
        self.PROJECT_LANGUAGE = kwargs.get('project_language')
        self.ROOT_CAUSE_REPORT = kwargs.get('root_cause_report')
        self.PATCH = kwargs.get('patch')
        

    def get_input_vars(self, *args, **kw):
        # Any returned dict will be use as an input to template the prompts
        # of this agent.
        vars = super().get_input_vars(*args, **kw)
        vars.update(
            PROJECT_NAME = self.PROJECT_NAME,
            PROJECT_LANGUAGE = self.PROJECT_LANGUAGE,
            ROOT_CAUSE_REPORT = self.ROOT_CAUSE_REPORT,
            PATCH = self.PATCH
        )
        return vars
    
    # def get_available_tools(self):
    #     # TODO: maybe activate tools in a smarter way here...
    #     my_tools = []
    #     my_tools.extend(ALL_TOOLS.values())
        
    #     if Config.use_lang_server:
    #         my_tools.extend(LANG_SERVER_TOOLS.values())
            
    #     if Config.use_codeql_server:
    #         my_tools.extend(CODEQL_TOOLS.values())
            
    #     return my_tools

    def get_output_parser(self):
        return MyParser(critic_guy=self)
    