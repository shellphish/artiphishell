import logging

from typing import Dict, Tuple
from patchery.generator.tool import Tool

from .prompt_generator import PromptGenerator
from .llm_utils import post_llm_requests, parse_llm_output

_l = logging.getLogger(__name__)


class LLMTools(Tool):
    def __init__(self, prompt_template: str, prompt_args: Dict, model='oai-gpt-4o'):
        self.prompt_template = prompt_template
        self.prompt_args = prompt_args
        self.model = model
        self.temperature = 0.0
        self.cost = 0.0
        self.thinking = False
        super().__init__(self.prompt_template, self.prompt_args)

    def generate_prompt(self) -> str:
        prompt = PromptGenerator.render(self.prompt_template, self.prompt_args)
        return prompt

    def call_llm(self) -> Tuple[str, float]:
        prompt = self.generate_prompt()
        _l.debug(f"Prompt Length: {len(prompt)}")
        # we can always use the user role
        response, cost = post_llm_requests(messages=[{"role": "system", "content": prompt}, {"role": "user",
                                                                                             "content": "follow the instruction in the system prompt below"}],
                                           temperature=self.temperature,
                                           model=self.model, enable_thinking=True)
        content = parse_llm_output(response, self.model)
        return content, cost
