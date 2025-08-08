
import logging
import re
from agentlib import LocalObject, ObjectParser, Field, tools, LLMFunction
from agentlib import AgentWithHistory, LocalObject, ObjectParser, Field, tools, Agent
from agentlib.lib.common.parsers import BaseParser

from ..toolbox.peek_src_dumb import show_file_at_simple, lookup_symbol_simple
from typing import Optional, Any

logger = logging.getLogger('PatchBypassGuy')
# Bypass metadata is going to contain the following:
# project_id
# patch_id
# crashing_input_id
# patch_description

class MyParser(BaseParser):
    recover_with = 'gpt-o4-mini'
    __OUTPUT_DESCRIPTION = '/src/discoveryguy/prompts/PatchBypass/BypassGuyReport.txt'
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.patch_bypass = kwargs.get('patch_bypass')
    
    def invoke(self, msg, *args, **kwargs) -> dict:
        return self.parse(msg['output'])

    def get_format_instructions(self) -> str:
        # This string is used in the user prompt as {{output_format}}
        output_format = open(self.__OUTPUT_DESCRIPTION, 'r').read()
        return output_format

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

    def parse(self, text: str) -> dict:
        # print(f"Parsing text: {text}")
        # I want to extract the script in between <python_script> tags
        try_iter = 1
        summary = None
        script = None
        
        while try_iter <= 3:
            script_match = re.findall(r'<python_script>(.*?)</python_script>', text, re.DOTALL)
            summary_match = re.findall(r'<summary>(.*?)</summary>', text, re.DOTALL)
            if script_match and summary_match:
                try:
                    script = script_match[-1].strip()
                    summary = summary_match[-1].strip()
                    break 
                except Exception as e:
                    logger.error(f"Error extracting script or summary: {e}")
                    self.fix_format(text)
            else:
                logger.info(f"Failed to find script or summary in text: {text}")
                text = self.fix_format(text)
            try_iter += 1

        bypass_summary = {
            'exploit_script': script,
            'summary': summary
        }
        return bypass_summary

class PatchBypass(AgentWithHistory[dict,str]):

    # Choose a language model to use (default gpt-4-turbo)
    __LLM_MODEL__ = "claude-3.7-sonnet"
    # __LLM_ARGS__ = {"temperature": 0.2}
    # __LLM_MODEL__ = "claude-4-opus"

    # Lets keep it simple for now
    __MAX_TOOL_ITERATIONS__ = 50

    __SYSTEM_PROMPT_TEMPLATE__ = '/src/discoveryguy/prompts/PatchBypass/system.j2'
    __USER_PROMPT_TEMPLATE__ = '/src/discoveryguy/prompts/PatchBypass/user.j2'

    __RAISE_ON_BUDGET_EXCEPTION__ = True
    
    LANGUAGE_EXPERTISE: str = None
    PATCH_CODE: str = None
    SUMMARY: str = None
    STACK_TRACE: str = None
    FEEDBACK: str = None
    CRASHING_INPUT: str = None
    __OUTPUT_PARSER__ = MyParser

    __LOGGER__ = logging.getLogger('PatchBypassGuy')
    __LOGGER__.setLevel(logging.ERROR)

    HUMAN_MSG: Optional[str] = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.LANGUAGE_EXPERTISE = kwargs.get('LANGUAGE_EXPERTISE')
        self.PATCH_CODE = kwargs.get('PATCH_CODE')
        self.SUMMARY = kwargs.get('SUMMARY')
        self.STACK_TRACE = kwargs.get('STACK_TRACE')
        self.FEEDBACK = kwargs.get('FEEDBACK')
        self.CRASHING_INPUT = kwargs.get('CRASHING_INPUT')
        self.HUMAN_MSG = kwargs.get('HUMAN_MSG', None)

        if len(self.CRASHING_INPUT) > 4096:
            try:
                self.CRASHING_INPUT = "Crashing Input is too long to show you but here's the first 4096 characters:\n" + self.CRASHING_INPUT[:4096]
            except Exception as e:
                print(f"Error truncating crashing input: {e}")
                self.CRASHING_INPUT = "Crashing Input is too long to show you."


    def get_input_vars(self, *args, **kw):
        vars = super().get_input_vars(*args, **kw)
        vars.update({
            'LANGUAGE_EXPERTISE': self.LANGUAGE_EXPERTISE,
            'PATCH': self.PATCH_CODE,
            'SUMMARY': self.SUMMARY,
            'STACK_TRACE': self.STACK_TRACE,
            'FEEDBACK': self.FEEDBACK,
            'CRASHING_INPUT': self.CRASHING_INPUT,
            'HUMAN_MSG' : self.HUMAN_MSG
        })
        return vars
    
    def get_available_tools(self): 
        return [
            show_file_at_simple,
            lookup_symbol_simple
        ]

    def get_output_parser(self):
        return MyParser(patch_bypass=self)

    def set_human_msg(self, human_msg: str):
        self.HUMAN_MSG = human_msg
