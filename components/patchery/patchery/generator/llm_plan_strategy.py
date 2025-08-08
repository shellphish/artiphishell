import logging

from jinja2 import Template, StrictUndefined

from .llm_tools import LLMTools
from .prompts.strategy_prompts import STRATEGY_PROMPT
from kumushi.data import PoICluster

_l = logging.getLogger(__name__)
class LLMPlanStrategy:
    def __init__(self, vulnerability_type: str, tools: LLMTools, poi_cluster: PoICluster):
        self.vulnerability_type = vulnerability_type
        self.tools = tools

    def execute_segv_strategy(self) -> str:
        _l.debug("🤪Executing SEGV strategy")
        summary = self.tools.tool_code_summarization()
        template = Template(STRATEGY_PROMPT, undefined=StrictUndefined)
        prompt = template.render(SUMMARY=summary)
        _l.debug(f"🔨 SEGV strategy prompt generated: {prompt}")
        return prompt


    # we choose strategy based on the type of vulnerability
    def execute_strategy(self)-> str:
        #FIXME: add more strategies
        if self.vulnerability_type.strip() == "AddressSanitizer: SEGV":
            return self.execute_segv_strategy()
        else:
            return self.execute_segv_strategy()
