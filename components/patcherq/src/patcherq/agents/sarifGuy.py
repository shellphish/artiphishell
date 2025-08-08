
import re
import logging
from jinja2 import Template
import json

from agentlib import AgentWithHistory, LLMFunction
from agentlib.lib.common.parsers import BaseParser
from typing import Optional, Any
from jsonschema import validate
# from ..toolbox.peek_logs import show_log_at

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class MyParser(BaseParser):
    
    __OUTPUT_DESCRIPTION = '/src/patcherq/prompts/sarifGuy/sarifGuy.output.txt'
    
    # The maximum number of attempts to fix the format of the report
    MAX_PATCH_FORMAT_FIX_ATTEMPTS = 3

    # Extra cost that we need to keep track when we do LLM calls
    llm_extra_calls_cost = 0

    # The model used to recover the format of the patch report
    recover_with = 'gpt-4.1-mini'
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def get_format_instructions(self) -> str:
        output_format = open(self.__OUTPUT_DESCRIPTION, 'r').read()
        return output_format
    
    def invoke(self, msg, *args, **kwargs) -> dict:
        return self.parse(msg.content)
    
    def fix_format(self, text: str, data_fix: bool = False) -> str:
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
                output_format = self.get_format_instructions(),
                data_fix = data_fix,
            )
        )

        return fixed_text

    def parse(self, text: str):
        print("raw text", text)
        def extract(tag: str) -> str:
            m = re.search(rf'<{tag}>\s*(.*?)\s*</{tag}>', text, re.DOTALL)
            return m.group(1) if m else ''
        
        try_itr = 1
        error = None
        while try_itr <= 3:
            rule_id          = extract('rule_id')
            rule_name        = extract('rule_name')
            rule_description = extract('rule_description')
            level            = extract('level')

            # Extract all flow items
            flows_raw = re.search(r'<flow>\s*(.*?)\s*</flow>', text, re.DOTALL)
            flow_pattern = (
                r'<flow_item>\s*'
                r'<filepath>\s*(.*?)\s*</filepath>\s*'
                r'<startline>\s*(.*?)\s*</startline>\s*'
                r'</flow_item>'
            )
            flow_items = re.findall(flow_pattern, flows_raw.group(1) if flows_raw else '', re.DOTALL)
            
            if not flow_items or not rule_id or not rule_name or not rule_description or not level:
                # Technically, this should never happen
                # the parser should make sure that the output is always in the format.
                logger.info('🤡 Regexp-Error: Error parsing the sarif report! %s', error if error else "")
                logger.info('🤡 Regexp-Error: Trying to fix the format of the sarif report... Attempt %d!', try_itr)
                text = self.fix_format(text)
                try_itr += 1
                continue 

            return {
                'RULE_ID': rule_id,
                'RULE_NAME': rule_name,
                'RULE_DESCRIPTION': json.dumps(rule_description),
                'LEVEL': level,
                'FLOW': flow_items
            }
                
class SARIFGuy(AgentWithHistory[dict,str]):
    __LLM_MODEL__ = 'gpt-4o'

    __SYSTEM_PROMPT_TEMPLATE__ = '/src/patcherq/prompts/sarifGuy/sarifGuy.system.j2' 
    __USER_PROMPT_TEMPLATE__ = '/src/patcherq/prompts/sarifGuy/sarifGuy.user.j2'
    
    __LLM_ARGS__ = {
        'temperature': 0.0,
        'max_tokens': 8192
    }

    __RAISE_ON_BUDGET_EXCEPTION__ = True
    
    PROGRAM_NAME: Optional[str]
    POI_REPORT: Optional[str]
    ROOT_CAUSE_REPORT: Optional[str]
    PATCH: Optional[str]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.PROGRAM_NAME = kwargs.get('project_name')
        self.POI_REPORT = kwargs.get('poi_report')
        self.ROOT_CAUSE_REPORT = kwargs.get('root_cause_report')
        self.PATCH = kwargs.get('patch')

        assert(self.PROGRAM_NAME is not None)
        assert(self.POI_REPORT is not None)
        assert(self.ROOT_CAUSE_REPORT is not None)
        assert(self.PATCH is not None)
        assert(self.PROGRAM_NAME != "")
        assert(self.POI_REPORT != "")
        assert(self.ROOT_CAUSE_REPORT != "")
        assert(self.PATCH != "")

    def get_input_vars(self, *args, **kw):
        # Any returned dict will be use as an input to template the prompts
        # of this agent.
        vars = super().get_input_vars(*args, **kw)
        vars.update(
            PROGRAM_NAME=self.PROGRAM_NAME,
            POI_REPORT=self.POI_REPORT,
            ROOT_CAUSE_REPORT=self.ROOT_CAUSE_REPORT,
            PATCH=self.PATCH
        )
        return vars
    
    # def set_feedback(self, failure_reason=None, feedback=None, **kwargs):
    #     assert(feedback is not None)
    #     assert(failure_reason is not None)

    #     self.IS_FEEDBACK = True
    #     self.FAILURE_REASON = failure_reason

    def validate_sarif(self, sarif: str) -> bool:
        schema = json.load(open('/src/patcherq/schemas/sarifSchema.json'))
        try:
            sarif = json.loads(sarif)
            validate(instance=sarif, schema=schema)
            return True
        except:
            logger.info('Bad sarif: %s', sarif)
            return False
    
    def generate_sarif(self, sarif_keys: dict) -> str:
        with open('/src/patcherq/schemas/sarif.j2', 'r') as file:
            template_string = file.read()
            
        template = Template(template_string)
        return template.render(sarif_keys)
        
    def get_output_parser(self):
        return MyParser()
