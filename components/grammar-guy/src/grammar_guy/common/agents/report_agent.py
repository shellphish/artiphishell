
import logging
import os

# Agentlib and CRS Utils stuff 
from agentlib import Agent
from agentlib import Agent, LLMFunction
from agentlib.lib.common.parsers import BaseParser

# grammar-guy imports
os.chdir(os.path.dirname(__file__))
from grammar_guy.common.improvement_strategies import *
from grammar_guy.common import config
from grammar_guy.common.utils import *

OUTPUT_DESCRIPTION = '''
After completing the analysis, you MUST output the report in the following specified format.

```
<grammar_report>
<report>...</report>
</grammar_report>
```

Within the `<report>...</report>` tags, replace the `...` with the valid and non-empty report (string) that you have created to the grammar composer.
'''

class MyParser(BaseParser):
    MAX_FORMAT_FIX_ATTEMPTS = 3
    RECOVERY_MODEL = 'gpt-4.1-mini'

    def get_format_instructions(self) -> str:
        return OUTPUT_DESCRIPTION

    def invoke(self, msg, *args, **kwargs) -> dict:
        return self.parse(msg.content)

    def fix_format(self, text: str) -> str:
        fix_llm = LLMFunction.create(
            'Fix the format of the current report according to the format instructions.\n\n# CURRENT REPORT\n{{ info.current_report }}\n\n# OUTPUT FORMAT\n{{ info.output_format }}',
            model=self.RECOVERY_MODEL,
            temperature=0.0
        )
        fixed_text = fix_llm(
            info = dict(
                current_report = text,
                output_format = self.get_format_instructions()
            )
        )
        return fixed_text

    def raise_format_error(self) -> None:
        raise ValueError(f'🤡 Output format is not correct!!')

    def parse(self, text: str) -> dict:
        try_itr = 1
        while try_itr <= self.MAX_FORMAT_FIX_ATTEMPTS:
            try:
                m = re.search(r'<report>(.*?)</report>', text, re.DOTALL)
                report = m.group(1).strip() if m else self.raise_format_error()
                return dict(
                    raw_text=text,
                    report=report.strip()
                )
            except ValueError:
                text = self.fix_format(text)
                try_itr += 1

class ReportAgent(Agent[dict,str]):
    __LOGGER__ = logging.getLogger('ReportAgent')
    __LOGGER__.setLevel('ERROR')
    __OUTPUT_PARSER__ = MyParser

    def get_input_vars(self, *args, **kw):
        vars = super().get_input_vars(*args, **kw)
        return vars

    def get_cost(self, *args, **kw) -> float:
        total_cost = 0
        # We have to sum up all the costs of the LLM used by the agent
        for model_name, token_usage in self.token_usage.items():
            total_cost += token_usage.get_costs(model_name)['total_cost']
        return total_cost

def submit_report(report: str) -> str:
    '''
    This function is used to submit the report that you have created to the grammar composer. Remember that you are not allowed to truncate the report.
    Use this function every time you have finished generating a report and want to return it to the agent. 
    params report: The report that was produced. The string provided as a parameter must be a valid report.
    returns report: The report that was produced.
    '''
    if report == '':
        return "The report string is empty! Please go back and write a valid report. Then pass it as a parameter to this function."
    config.set_new_report(report)
    if config.get_new_report() is None:
        raise ValueError("The report string is empty! Please go back and write a valid report. Then pass it as a parameter to this function.")
    else:
        # log.info(f"Retrieved report: \n {config.get_new_grammar()}")
        return config.get_new_report()

def setup_report_agent(
        system_prompt_template:str = 'report.system.j2', 
        user_prompt_template:str = 'report.user.j2', 
        llm_model:str = 'o3'
    ):
    ''' Initialize OpenAI client with API key
    :return: OpenAI client
    :rtype: OpenAI
    '''
    agent = ReportAgent(
        __SYSTEM_PROMPT_TEMPLATE__  = f'{config.FUZZER_NAME}/{system_prompt_template}',
        __USER_PROMPT_TEMPLATE__    = f'{config.FUZZER_NAME}/{user_prompt_template}',
        __LLM_MODEL__               = llm_model,
    )
    agent.use_web_logging_config(clear=True)
    return agent

