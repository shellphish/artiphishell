import re
import logging

from agentlib import Agent, LLMFunction
from agentlib.lib.common.parsers import BaseParser

logger = logging.getLogger('GrammarAgent')
logger.setLevel(logging.INFO)

OUTPUT_DESCRIPTION = '''
After completing the analysis, you MUST output the report in the following specified format.

```
<grammar_report>
<grammar>...</grammar>
</grammar_report>
```

Within the `<grammar>...</grammar>` tags, replace the `...` with the valid and non-empty grammar string that you have generated.
'''

class MyParser(BaseParser):
    MAX_FORMAT_FIX_ATTEMPTS = 3
    RECOVERY_MODEL = 'gpt-4.1-mini'

    def get_format_instructions(self) -> str:
        return OUTPUT_DESCRIPTION

    def invoke(self, msg, *args, **kwargs) -> dict:
        return self.parse(msg.content)

    def fix_format(self, text: str) -> str:
        logger.info(f'🚨 No Tool - Text = {text}')
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
        logger.info(f'🚨 Fixed Text = {fixed_text}')
        return fixed_text

    def raise_format_error(self) -> None:
        raise ValueError(f'🤡 Output format is not correct!!')

    def parse(self, text: str) -> dict:
        try_itr = 1
        while try_itr <= self.MAX_FORMAT_FIX_ATTEMPTS:
            logger.info(f'💬 Text: {text}')
            try:
                m = re.search(r'<grammar>(.*?)</grammar>', text, re.DOTALL)
                grammar = m.group(1).strip() if m else self.raise_format_error()
                return dict(
                    raw_text=text,
                    grammar=grammar.strip()
                )
            except ValueError:
                text = self.fix_format(text)
                try_itr += 1

class GrammarAgentNoTool(Agent[dict,str]):
    __LOGGER__ = logging.getLogger('GrammarAgent')
    __LOGGER__.setLevel('INFO')
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
