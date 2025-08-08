import logging
from typing import Dict, Optional

from .tool import Tool
from .prompt_generator import PromptGenerator
from .prompts.one_shot_prompts import WRONG_PATCH, WRONG_PATCH_REASONING
from ..data import Patch

_l = logging.getLogger(__name__)

class PatchPromptTool(Tool):
    def __init__(self, prompt_template: str, prompt_args: Dict, failed_patch: Optional[Patch]= None):
        self.prompt_template = prompt_template
        self.failed_patch = failed_patch
        self.prompt_args = prompt_args
        if self.failed_patch is not None:
            if self.failed_patch.diff:
                failed_patch_diff = 'You previous patch is wrong and here is the reason why and the diff of the wrong patch. \n Analyse the diff and the reason and fix the patch.\n' + self.failed_patch.diff
            else:
                failed_patch_diff = ''
            self.prompt_args["WRONG_PATCH"] = PromptGenerator.render(WRONG_PATCH, {"WRONG_PATCH": failed_patch_diff}) if failed_patch_diff else ''
            failed_patch_reasoning = self.failed_patch.reasoning
            if 'Bug still triggered' == self.failed_patch.reasoning:
                failed_patch_reasoning = 'Bug still triggered after patching'
            self.prompt_args["WRONG_PATCH_REASONING"] = PromptGenerator.render(WRONG_PATCH_REASONING, {"REASONING": failed_patch_reasoning})
        super().__init__(prompt_template, self.prompt_args)

    def generate_prompt(self) -> str:
        prompt = PromptGenerator.render(self.prompt_template, self.prompt_args)
        return prompt