import logging
import re
from agentlib import LocalObject, ObjectParser, Field, tools, LLMFunction, SaveLoadObject
from agentlib import AgentWithHistory, LocalObject, ObjectParser, Field, tools, Agent
from agentlib.lib.common.parsers import BaseParser

from ..toolbox.peek_src import get_function_definition
from ..toolbox import lookup_symbol
from typing import Optional, Any

logger = logging.getLogger('Scanner')

class ScanParser(BaseParser):
    # The model used to recover the format of the patch report
    # This is the output format that describes the output of ScanParser
    __OUTPUT_DESCRIPTION = '/src/scanguy/prompts/HongweiValidate/HongweiValidate.output.txt'
    __CONTEXT_WINDOW_EXCEEDED_STRATEGY__ = 'throw_exception'

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.exp_dev = kwargs.get('exp_dev')

    def get_format_instructions(self) -> str:
        # This string is used in the user prompt as {{output_format}}
        output_format = open(self.__OUTPUT_DESCRIPTION, 'r').read()
        return output_format

    def invoke(self, msg, *args, **kwargs) -> dict:
        return self.parse(msg['output'])

    def parse(self, text: str) -> dict:
        """
        Parse the model output and return a dictionary containing:
        - output: the combined <reasoning_process> and <vuln_detect> sections
        - predicted_is_vulnerable: 'yes', 'no', or 'invalid format'
        - predicted_vulnerability_type: CWE identifier or 'N/A'
        """
        # Extract the <reasoning_process> section
        think_match = re.search(r'(<reasoning_process>[\s\S]*?</reasoning_process>)', text)
        # Extract the <vuln_detect> section
        vuln_match = re.search(r'(<vuln_detect>[\s\S]*?</vuln_detect>)', text)

        if think_match and vuln_match:
            combined_output = think_match.group(1) + "\n" + vuln_match.group(1)

            # Extract the vulnerability judgment and type
            judge_match = re.search(r'#judge:\s*(yes|no)', vuln_match.group(1), re.IGNORECASE)
            type_match  = re.search(r'#type:\s*([A-Za-z0-9\-]+)', vuln_match.group(1), re.IGNORECASE)

            predicted_is_vulnerable = judge_match.group(1).lower() if judge_match else "invalid format"
            predicted_vulnerability_type = type_match.group(1).upper() if type_match else "N/A"

            # If not vulnerable, enforce type as N/A
            if predicted_is_vulnerable == "no":
                predicted_vulnerability_type = "N/A"

            return {
                "output": combined_output,
                "predicted_is_vulnerable": predicted_is_vulnerable,
                "predicted_vulnerability_type": predicted_vulnerability_type
            }
        return {
            "output": text,
            "predicted_is_vulnerable": "invalid format",
            "predicted_vulnerability_type": "N/A"
        }


class HongweiValidate(AgentWithHistory[dict, str]):
    # __LLM_ARGS__ = {"temperature": 1.0}
    # __LLM_MODEL__ = "claude-3.7-sonnet"
    # __LLM_MODEL__ = "claude-4-sonnet"
    # __LLM_MODEL__ = "o4-mini"
    # __LLM_MODEL__ = "o3"
    __LLM_MODEL__ = "best_n_no_rationale_poc_agent_withjava_final_model_agent_h100"
    __CONTEXT_WINDOW_EXCEEDED_STRATEGY__ :dict = dict(name='throw_exception')


    __LLM_ARGS__ = {
        'max_tokens': 2000,
    }

    __SYSTEM_PROMPT_TEMPLATE__ = "/src/scanguy/prompts/HongweiValidate/system.j2"
    __USER_PROMPT_TEMPLATE__ = "/src/scanguy/prompts/HongweiValidate/user.j2"

    __MAX_TOOL_ITERATIONS__ = 5
    __RETRIES_ON_TOOL_VALIDATION_ERROR__ = 3
    __OUTPUT_PARSER__ = ScanParser

    CODE : str = None
    NODES : list = None
    CWE_PROMPT : str = None


    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.CODE = kwargs["CODE"]
        self.NODES = kwargs["NODES"]
        self.CWE_PROMPT = kwargs.get("CWE_PROMPT", None)
        self.REASONING = kwargs.get("REASONING", None)
        if self.NODES and (self.NODES[-1].get('code', "") == self.CODE):
            self.NODES = self.NODES[:-1]
        max_len = 50000
        cur_len = len(self.CODE)
        selected_nodes = []
        for node in self.NODES[::-1]:
            if len(node.get('code', "")) + cur_len < max_len:
                selected_nodes.append(node)
                cur_len += len(node.get('code', ""))
            else:
                break

        self.CODE_SNIPPET_TO_SCAN = "<context>\n" + "\n".join([node.get('code', "") for node in selected_nodes])+ "</context>\n<target_function>\n" + self.CODE+ "</target_function>"

    def get_input_vars(self, *args, **kw):
        vars = super().get_input_vars(*args, **kw)
        vars.update(
            CODE=self.CODE_SNIPPET_TO_SCAN,
            INITIAL_REASONING=self.REASONING if self.REASONING else "",
            CWE_PROMPT=self.CWE_PROMPT if self.CWE_PROMPT else "Please check any possible CWE vulnerabilities in the code snippet.",
        )
        return vars

    def get_available_tools(self):
        # import ipdb; ipdb.set_trace()
        # lookup_symbol
        return [get_function_definition]

    def get_output_parser(self):
        return ScanParser(exp_dev=self)