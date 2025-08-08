
import re
from agentlib import Agent, LLMFunction
from agentlib.lib.common.parsers import BaseParser
from typing import Optional, Any

class MyParser(BaseParser):
    def get_format_instructions(self) -> str:
        # This string is used in the user prompt as {{output_format}}
        return 'In case of positive answer the output is <answer>YES</answer>, otherwise, <answer>NO</answer>'
    
    def invoke(self, msg, *args, **kwargs) -> dict:
        return self.parse(msg.content)
    
    def fix_patch_format(self, text: str) -> str:
        fix_llm = LLMFunction.create(
            'Fix the format of the current report according to the format instructions.\n\n# CURRENT REPORT\n{{ info.current_report }}\n\n# OUTPUT FORMAT\n{{ info.output_format }}',
            model='gpt-4.1-mini',
            use_loggers=True,
            temperature=0.0
        )
        fixed_text = fix_llm(
            info = dict(
                current_report = text,
                output_format = self.get_format_instructions()
            )
        )
        return fixed_text

    def parse(self, text: str):
        # Catch everything between <ANSWER> and </ANSWER>
        # and return the content of the tag
        try_itr = 1
        while try_itr <= 3:
            m = re.search(r'<answer>(.*?)</answer>', text)
            if m:
                print('✅ Regexp-Parser: Successfully parsed the diffGuy report from the output!')
                return m.group(1)
            else:
                # Technically, this should never happen
                # the parser should make sure that the output is always in the format.
                print(f'🤡 Regexp-Error: Error parsing the diffGuy report!')
                print(f'🤡 Regexp-Error: Trying to fix the format of the diffGuy report... Attempt {try_itr}!')
                text = self.fix_patch_format(text)
                try_itr += 1


class DiffGuy(Agent[dict,str]):
    __LLM_MODEL__ = 'gpt-4o'

    __SYSTEM_PROMPT_TEMPLATE__ = '/src/patcherq/prompts/diffGuy/diffGuy.system.j2' 
    __USER_PROMPT_TEMPLATE__ = '/src/patcherq/prompts/diffGuy/diffGuy.user.j2'
    __OUTPUT_PARSER__ = MyParser

    PROJECT_NAME: Optional[str]
    PROJECT_LANGUAGE: Optional[str]
    FILE_CHANGED: Optional[str]
    FILE_DIFF: Optional[str]
    POI_REPORT: Optional[str]
    REASON: Optional[str]
    SANITIZER: Optional[str]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.PROJECT_NAME = kwargs.get('project_name')
        self.PROJECT_LANGUAGE = kwargs.get('project_language')
        self.FILE_CHANGED = kwargs.get('file_changed')
        self.FILE_DIFF = kwargs.get('file_diff')
        self.POI_REPORT = kwargs.get('poi_report')
        self.REASON = kwargs.get('reason')
        self.SANITIZER = kwargs.get('sanitizer')

    def get_input_vars(self, *args, **kw):
        # Any returned dict will be use as an input to template the prompts
        # of this agent.
        vars = super().get_input_vars(*args, **kw)
        vars.update(
            PROJECT_NAME=self.PROJECT_NAME,
            PROJECT_LANGUAGE=self.PROJECT_LANGUAGE,
            FILE_CHANGED=self.FILE_CHANGED,
            FILE_DIFF= self.FILE_DIFF,
            POI_REPORT=self.POI_REPORT,
            REASON=self.REASON,
            SANITIZER=self.SANITIZER
        )
        return vars