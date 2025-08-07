import logging
from typing import Optional

from jinja2 import Template, StrictUndefined
from openai import OpenAI

from .llm_patch_generator import LLMPatchGenerator
from ..data import AICCProgramInfo
from .prompts.invariance_prompts import (
    INITIAL_PROMPT,
    RAG_EXAMPLE,
    FAILED_PATCH_PROMPT,
    CRASH_COMMIT_DIFF,
    GLOBAL_VARIABLES,
    DEBUG_INFORMATION,
    FORMAT_EXAMPLE,
    JAVA_FORMAT_EXAMPLE
)
from ..data import InvarianceReport
from .. import Patch
from ..data import ProgramPOI

_l = logging.getLogger(__name__)


class InvariantLLMPatchGenerator(LLMPatchGenerator):
    def _generate_patch_one_shot(
        self,
        poi: ProgramPOI,
        report,
        failed_patch: Optional[Patch] = None,
        invariance_report: Optional[InvarianceReport] = None,
        **kwargs
    ) -> Optional[Patch]:
        # TODO: support EXAMPLE from other prompting styles
        # TODO: support THREE_EXPERTS_PROMPT
        crash_commit_diff = ""
        if poi.git_diff:
            GIT_DIFF = poi.git_diff
            diff_template = Template(CRASH_COMMIT_DIFF, undefined=StrictUndefined)
            diff_template_args = {"GIT_DIFF": GIT_DIFF}
            crash_commit_diff = diff_template.render(diff_template_args)

        debug_information = ""
        format_example = ""
        if self._is_java_target():
            format_example = JAVA_FORMAT_EXAMPLE
            _l.info(f"☕We are patching JAVA!")
        else:
            _l.info(f"🙈We are patching C!")            
            format_example = FORMAT_EXAMPLE
            if poi.debug_info:
                DEBUG_INFO = poi.debug_info
                debug_template = Template(DEBUG_INFORMATION, undefined=StrictUndefined)
                debug_template_args = {"DEBUG_INFO": DEBUG_INFO}
                debug_information = debug_template.render(debug_template_args)

        if invariance_report is None:
            raise ValueError("Invariance report is required for invariant patch generation.")

        source = self.get_source(poi)
        # crash_loc = self.read_crash_loc(poi)
        # vuln_loc = ""
        # if crash_loc:
        #     CRASH_LOC = crash_loc
        #     vuln_loc_template = Template(VULNERABLE_LOC, undefined=StrictUndefined)
        #     vuln_loc_template_args = {"CRASH_LOC": CRASH_LOC}
        #     vuln_loc = vuln_loc_template.render(vuln_loc_template_args)
        invariant_loc = self.read_invariant_loc(poi)

        unique_to_crash = invariance_report.unique_to_crash
        
        global_vars = ""
        if poi.global_variables:
            global_variables_template = Template(GLOBAL_VARIABLES, undefined=StrictUndefined)
            global_variables_template_args = {"GLOBALS": "\n".join(poi.global_variables)}
            global_vars = global_variables_template.render(global_variables_template_args)
        
        example = ""
        if isinstance(self.source_info, AICCProgramInfo) and self.source_info.sanitizer_string:
            FUNC_DIFF = self.retrieve_example(self.get_source(poi), self.source_info.sanitizer_string)
        else:
            FUNC_DIFF = self.retrieve_example(self.get_source(poi))
        
        if FUNC_DIFF != "":
            example_template = Template(RAG_EXAMPLE, undefined=StrictUndefined)
            example_template_args = {"FUNC_DIFF": FUNC_DIFF}
            example = example_template.render(example_template_args)   

        extra_args = {}
        if failed_patch is None or (not self.use_failed_patch_reasoning and not self.use_failed_patch_code):
            prompt = INITIAL_PROMPT
        else:
            prompt = FAILED_PATCH_PROMPT
            extra_args = {
                "WRONG_PATCH": failed_patch.new_code,
                "REASONING": failed_patch.reasoning,
            }
        prompt_args = {
            "INV_REPORT": invariance_report.render(),
            "REPORT": report,
            "SOURCE": source,
            "EXAMPLE": example,
            "FORMAT_EXAMPLE": format_example,
            "CRASH_COMMIT_DIFF": crash_commit_diff,
            "GLOBAL_VARIABLES": global_vars,
            "INVARIANT_LINE": invariant_loc,
            "DEBUG_INFORMATION": debug_information,
            "unique_to_crash": unique_to_crash,
            "use_failed_patch_reasoning": self.use_failed_patch_reasoning,
            "use_failed_patch_code": self.use_failed_patch_code,
            "use_expert_reasoning": self.use_expert_reasoning,
        }
        prompt_args.update(extra_args)

        debug_prompt_template = Template(prompt, undefined=StrictUndefined)
        debug_prompt = debug_prompt_template.render(prompt_args)
        original_prompt = [
            {"role": "user", "content": "follow the instruction in the system prompt below"},
            {"role": "system", "content": debug_prompt},
        ]
        _l.debug(f"💭 Prompting with prompt len={len(debug_prompt)}")
        _l.info(f"💭 Prompting with prompt: {debug_prompt}")
        final_patch, self.cost = self._generate_patch_in_loop(original_prompt)
        return self._parse_patch_from_response(final_patch, poi, self.get_source(poi))

    def _generate_patch_many_shot(
        self, poi: ProgramPOI, report, failed_patch: Optional[Patch] = None, **kwargs
    ) -> Optional[Patch]:
        raise NotImplementedError("Invariant patch generator is not implemented yet for many-shot mode.")
