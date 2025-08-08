import logging
from typing import Optional, Dict, List
from patchery.utils import LLM_MAPPING
from .prompt_generator import PromptGenerator
from .llm_patch_generator import LLMPatchGenerator
from .llm_tools import LLMTools
from .patch_prompt_tool import PatchPromptTool
from .prompts.one_shot_planing_prompts import (
    DEBUG_INFORMATION,

)
from .prompts.one_shot_prompts import (
    VULNERABLE_LOC,
    GLOBAL_VARIABLES,
    JAVA_FORMAT_EXAMPLE, POI_SPECIFIC_INFO,
    SUMMARIZE_REPORTS_PROMPT,
    WRONG_PATCH,
    WRONG_PATCH_REASONING
)
from .prompts.plan_prompts import INITIAL_PROMPT, FAILED_PROMPT, FORMAT_EXAMPLE
from kumushi.data import PoICluster
from ..data import Patch

_l = logging.getLogger(__name__)


class LLMPlanPatchGenerator(LLMPatchGenerator):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.messages = []

    def append_message(self, message: Dict):
        self.messages.append(message)

    # show all tools
    def _show_tools(self):
        pass

    def _get_code_info(self, poi_cluster: PoICluster):
        debug_info_prompts = []
        for poi in poi_cluster.pois:
            crash_loc = self.read_crash_loc(poi)
            debug_info = ""
            if crash_loc:
                vuln_loc = PromptGenerator.render(VULNERABLE_LOC, {"CRASH_LOC": crash_loc})
                debug_info = debug_info + vuln_loc + "\n"
            if poi.function.global_vars:
                global_vars_string = ""
                for global_var in poi.function.global_vars:
                    global_vars_string += global_var.declaration + '\n'
                global_vars = PromptGenerator.render(GLOBAL_VARIABLES, {"GLOBALS": global_vars_string})
                debug_info = debug_info + global_vars + '\n'
            if debug_info:
                debug_info_args = {"DEBUG_INFO": debug_info, "FUNC_NAME": poi.function}
                debug_info_prompt = PromptGenerator.render(DEBUG_INFORMATION, debug_info_args)
                debug_info_prompts.append(debug_info_prompt)

        return "\n".join(debug_info_prompts)

    def _get_source_info(self, poi_cluster: PoICluster):
        all_poi_info = ""
        for poi in poi_cluster.pois:
            source = self.get_source(poi)
            file_name_and_func_name = f"<File_Name> {poi.function.file_path} </File_Name>\n<Func_Name> {poi.function.name} </Func_Name>\n"
            poi_specific_info = PromptGenerator.render(POI_SPECIFIC_INFO,
                                                       {
                                                           "SOURCE": file_name_and_func_name + source,
                                                       })
            all_poi_info += poi_specific_info
        return all_poi_info

    # we have llm_tool contain all the tools
    # we have llm_plan_strategy contain all the strategies

    def generate_patch(
            self, poi_cluster: PoICluster, reports: Optional[List], failed_patch: Optional[Patch] = None,
            **kwargs
    ) -> Optional[Patch]:
        self.cost = 0
        self.use_expert_reasoning = True
        code_info_promots = self._get_code_info(poi_cluster)
        source_info_prompts = self._get_source_info(poi_cluster)

        vulnerability_summarization, cost = LLMTools(prompt_template=SUMMARIZE_REPORTS_PROMPT,
                                                     prompt_args={"REPORT": reports[0],
                                                                  "ALL_POI_INFO_SUMMARY": code_info_promots,
                                                                  "SOURCE": source_info_prompts},
                                                     model=LLM_MAPPING.get('claude-3.7-sonnet')).call_llm()
        self.cost += cost
        return self._generate_patch_one_shot(poi_cluster, reports, failed_patch=failed_patch,
                                             summary_prompt=vulnerability_summarization, **kwargs)

    def _generate_patch_one_shot(
            self, poi_cluster: PoICluster, reports: Optional[List], failed_patch: Optional[Patch] = None,
            summary_prompt="", **kwargs
    ) -> Optional[Patch]:
        file_func_patchcode = {}
        if self._is_java_target():
            format_example = JAVA_FORMAT_EXAMPLE
            _l.info(f"☕We are patching JAVA!")
        else:
            _l.info(f"🙈We are patching C!")
            format_example = FORMAT_EXAMPLE

        patch_prompt_template = FAILED_PROMPT
        self.poi_cluster = poi_cluster

        all_poi_info = self._get_source_info(poi_cluster)
        reports = reports or []
        prompt_args = {
            "REPORT": reports[0],
            "ALL_POI_INFO": all_poi_info,
            "FORMAT_EXAMPLE": format_example,
            "VUL_SUMMARY": summary_prompt,
            "use_failed_patch_reasoning": self.use_failed_patch_reasoning,
            "use_failed_patch_code": self.use_failed_patch_code,
            "use_expert_reasoning": self.use_expert_reasoning,
        }
        failed_reason = ""
        patch_prompt = ""
        output_prompt = ""
        for i in range(self._max_regenerate_for_format_error):
            if i > 0:
                if failed_patch is None:
                    failed_patch = Patch([], reasoning=failed_reason, diff="")
                else:
                    failed_patch.reasoning += f"\n{failed_reason}"
            patch_prompt = PatchPromptTool(patch_prompt_template, prompt_args, failed_patch=failed_patch).generate_prompt()
            _l.debug(f"💭 Prompting with prompt len={len(patch_prompt)}")
            _l.debug(f"💭 Prompting with prompt: {patch_prompt}")
            original_prompt = [
                {"role": "user", "content": "follow the instruction in the system prompt below"},
                {"role": "system", "content": patch_prompt},]
            file_func_patchcode, cost, output_prompt = self._generate_patch_in_loop(original_prompt, output_parser='search')
            self.cost += cost
            if file_func_patchcode:
                # dict[str, dict[str, str]] find if any of the str value in the dict is empty
                empty_values = any(
                    not patch_text for file_dict in file_func_patchcode.values() for patch_text in file_dict.values())
                if empty_values:
                    failed_reason = "The function code you used to generate patch must be the same as the function code in the prompt, please check your patch code."
                    _l.info("💾Format error found in the patch, empty values detected in the patch code.")
                    continue
                break
            else:
                failed_reason = "You generate the wrong patch format, please follow the format example in the prompt."
            _l.info("💾Format error found in the patch")
        self.prompt_history.append(patch_prompt)
        self.prompt_history.append(output_prompt)
        return self._parse_patch_from_response(file_func_patchcode, poi_cluster)
