import logging
import re
from pathlib import Path
from typing import List, Dict, Tuple
from typing import Optional

from crs_telemetry.utils import get_otel_tracer

from .llm_prompting_styles import LLMPromptingStyles
from .llm_utils import post_llm_requests, parse_llm_output, parse_search_patch, replace_search_patch
from .patch_prompt_tool import PatchPromptTool
from .prompt_generator import PromptGenerator
from .prompts.one_shot_prompts import (
    THREE_EXPERTS_PROMPT,
    THREE_EXPERTS_FAILED_PATCH_PROMPT,
    CRASH_COMMIT_DIFF,
    VULNERABLE_LOC,
    GLOBAL_VARIABLES,
    FORMAT_EXAMPLE,
    DEBUG_INFORMATION,
    JAVA_FORMAT_EXAMPLE,
    POI_SPECIFIC_INFO,
    SUMMARIZE_REPORTS_PROMPT,
    FAILED_PATCH_PROMPT
)
from kumushi.data import Program, PoI, PoISource, PoICluster
from ..data import Patch, PatchedFunction

tracer = get_otel_tracer()
_l = logging.getLogger(__name__)

class LLMPatchGenerator:
    def __init__(
            self,
            source_info: Program,
            model: str,
            prompt_style: Optional[LLMPromptingStyles] = None,
            use_failed_patch_code: bool = False,
            use_failed_patch_reasoning: bool = True,
            use_expert_reasoning: bool = True,
            max_continues: int = 3,
    ):

        self.model = model
        _l.debug(f"🔍 Using model: {self.model}")
        self.source_info = source_info
        self.prompt_style = prompt_style
        self._resolve_prompt_style()

        self.cost = 0.0
        self.retry_conn = 5
        self.temperature = 0.0
        self.poi_cluster = None
        self.use_failed_patch_code = use_failed_patch_code
        self.use_failed_patch_reasoning = use_failed_patch_reasoning
        self.use_expert_reasoning = use_expert_reasoning

        self._max_continues = max_continues
        self.total_continues = 0
        self._max_regenerate_for_format_error = 3
        self.prompt_history = []

    def _resolve_prompt_style(self):
        if self.prompt_style is None:
            self.prompt_style = LLMPromptingStyles.ONE_SHOT_EXPERTS
        _l.debug(f"We are enabling three experts prompt, {self.prompt_style}")

    def get_source(self, poi: PoI) -> str:
        if poi.function and poi.function.code:
            return poi.function.code

        funcs = self.source_info.code.functions_by_name(poi.function.name, focus_repo_only=True)
        if not funcs:
            _l.warning(f"Function {poi.function.name} not found in source code.")
            return ""
        #FIXME: what if there are two functions with the same name?
        func = funcs[0]
        return func.code

    @staticmethod
    def read_crash_loc(poi: PoI) -> Optional[str]:
        func_line_len = 0
        if poi.function.start_line and poi.function.end_line:
            func_line_len = poi.function.end_line - poi.function.start_line
        else:
            _l.warning(f"🚫 Missing function start or end line information")
            return None
        # if func_line_len < 30:
        #     return None
        if poi.crash_line_num:
            loc_prompt = (
                f"Here is the line of code that crashes in function {poi.function.name}:\n\n"
                f"{poi.crash_line}\n"
            )
            return loc_prompt
        return None

    def _parse_patch_from_response(self, file_func_patchcode: Dict[str, Dict[str, str]], poi_cluster, reasoning=None) -> \
    Optional[
        Patch]:
        patched_funcs = []
        for file in file_func_patchcode:
            for func in file_func_patchcode[file]:
                new_code = file_func_patchcode[file][func]
                for poi in poi_cluster.pois:
                    if (str(poi.function.file_path) in str(file) or str(file) in str(poi.function.file_path)) and poi.function.name == func:
                        old_code = self.get_source(poi)
                        init_start_line = poi.function.start_line
                        init_end_line = poi.function.end_line
                        patched_func = PatchedFunction(
                            function_name=func,
                            file=poi.function.file_path,
                            init_start_line=init_start_line,
                            init_end_line=init_end_line,
                            new_code=new_code,
                            old_code=old_code,
                        )
                        patched_funcs.append(patched_func)
        return self.propose_patch(patched_funcs, reasoning=reasoning)

    @tracer.start_as_current_span("patchery.generate_patch_in_loop")
    def _generate_patch_in_loop(self, original_prompt, output_parser="") -> Tuple[dict, float, str]:
        cost = 0.0
        # file_func_patchcode is a dictionary that stores dictionarys the function name and the patch code
        file_func_patchcode = dict()

        whole_output = ''
        response, llm_cost = post_llm_requests(original_prompt, self.temperature, self.model, enable_thinking=True)
        content = parse_llm_output(response, self.model)
        cost += llm_cost
        whole_output += content
        # GPT would return like c```patch code`` or java ```patch code```, this is ONLY true for GPT

        # Generate the patch until the stop_reason is not length
        count = 0
        # finish_reason = response["choices"][0]["finish_reason"]
        # while finish_reason == "length" and count < self._max_continues:
        #     _l.debug(f"continue generation")
        #     count += 1
        #     assistant_prompt = {"role": "assistant", "content": f"{whole_output}"}
        #     continue_generation_prompt = {"role": "system",
        #                                   "content": "You haven't complete the generation last time, continue the patch generation"}
        #     original_prompt.append(assistant_prompt)
        #     original_prompt.append(continue_generation_prompt)
        #     response, llm_cost = post_llm_requests(original_prompt, 0.0, self.model)  # this should be 0.0 for continuation
        #     content = parse_llm_output(response, self.model)
        #     cost += llm_cost
        #     whole_output += content

        # The patch code should be put after ### Final Patch Code
        if "Final Patch Code" in whole_output:
            whole_output = whole_output.rsplit("Final Patch Code", 1)[-1].strip()
        if 'File' in whole_output:
            whole_output = whole_output[whole_output.index('File'): ].strip()
        if '>>>>>>> REPLACE' in whole_output:
            whole_output = whole_output[: whole_output.rindex('>>>>>>> REPLACE')].strip() + '\n>>>>>>> REPLACE\n```'
        _l.debug(f"cleaned search/replace blockes: {whole_output}")
        if output_parser == "search":
            patches = parse_search_patch(whole_output)
            flat_patches = self._aggregate_llm_output_patches(patches)
            for patch in flat_patches:
                file_name = patch['file_name']
                tmp_function_name = patch['function_name']
                search_replace_pairs = patch['search_replace_pairs']

                # Get the function code
                function = None

                # for poi in self.poi_cluster.pois:
                #     if (str(poi.function.file_path) in file_name or file_name in str(poi.function.file_path)) and \
                #         (poi.function.name == tmp_function_name or poi.function.name == 'OSS_FUZZ_' + tmp_function_name):
                #         tmp_function_name = poi.function.name
                #         function = poi.function
                #         if not Path(file_name).exists():
                #             file_name = poi.function.file_path
                #         break

                # Find first matching POI using generator expression
                matched_poi = next((
                    poi for poi in self.poi_cluster.pois
                    if (str(poi.function.file_path) in file_name or file_name in str(poi.function.file_path)) and
                       (poi.function.name == tmp_function_name or poi.function.name == 'OSS_FUZZ_' + tmp_function_name)
                ), None)

                if matched_poi:
                    tmp_function_name = matched_poi.function.name
                    function = matched_poi.function
                    if not Path(file_name).exists():
                        file_name = matched_poi.function.file_path

                if function is None:
                    _l.debug(f"Function {tmp_function_name} not found in poi cluster.")
                    continue

                tmp_function_code = function.code
                function_name = function.name
                for pair in search_replace_pairs:
                    search_code = pair['search_code']
                    replace_code = pair['replace_code']
                    tmp_function_code = replace_search_patch(tmp_function_code, search_code, replace_code)
                new_function_code = tmp_function_code
                if file_name not in file_func_patchcode:
                    file_func_patchcode[file_name] = {}

                # Update the dictionary with the new function code
                file_func_patchcode[file_name].update({function_name: new_function_code})

        else:
            pattern = re.compile(
                r"```(?:cpp|c|java)\s*"  # Start with ```cpp, ```c, or ```java
                r"<File_Name>(.*?)</File_Name>\s*"  # Capture file name
                r"<Func_Name>(.*?)</Func_Name>\n*"  # Capture function name
                r"(.*?)"  # Capture code
                r"```(?!c|cpp|java)",  # End with ``` not followed by c, cpp, or java
                re.DOTALL  # Make . match newlines
            )

            matches = pattern.finditer(whole_output)

            for match in matches:
                file_name = match.group(1).strip()
                func_name = match.group(2).strip()
                code = match.group(3).strip()
                if file_func_patchcode.get(file_name) is None:
                    file_func_patchcode[file_name] = dict()
                file_func_patchcode[file_name][func_name] = code
        return file_func_patchcode, cost, whole_output

    def _is_java_target(self):
        return self.source_info.language.lower() == "java"

    def _generate_report_summary(self, prompt_args) -> Tuple[str, float]:
        cost = 0.0
        summarize_reports_prompt = PromptGenerator.render(SUMMARIZE_REPORTS_PROMPT, prompt_args)
        _l.debug(f"🔍 Summarizing reports with prompt len={len(summarize_reports_prompt)}")
        _l.debug(f"🔍 Summarizing reports with prompt: {summarize_reports_prompt}")
        response, cost = post_llm_requests([{"role": "system", "content": summarize_reports_prompt}], self.temperature,
                                     self.model)
        content = parse_llm_output(response, self.model)
        return content, cost

    def _aggregate_llm_output_patches(self, patches: list) -> list:
        """
        Aggregate the patches from the LLM output.
        """
        aggregated_patches = []
        file_func_map = {}

        for patch in patches:
            file_name = patch['file_name']
            function_name = patch['function_name']
            key = (file_name, function_name)

            if key not in file_func_map:
                new_entry = {
                    'file_name': file_name,
                    'function_name': function_name,
                    'search_replace_pairs': []
                }
                file_func_map[key] = new_entry
                aggregated_patches.append(new_entry)

            # Add search_replace_pairs from current patch to the aggregated one
            file_func_map[key]['search_replace_pairs'].extend(patch['search_replace_pairs'])

        return aggregated_patches

    @tracer.start_as_current_span("patchery.generate_patch_one_shot")
    def _generate_patch_one_shot(
            self, poi_cluster: PoICluster, reports, failed_patch: Optional[Patch] = None, **kwargs
    ) -> Optional[Patch]:
        # Collect poi-specific information, construct the part of the prompt that is specific to each POI

        all_poi_info = ""
        all_poi_info_summary = ""
        actual_crash_loc = "line of code in the stack trace leading to the crash"
        report_prompt = ""
        reports = reports or []

        for report in reports:
            _l.debug(f"📜Report type is: {report.__repr__()}")

        # TODO: this is really bad, what if we have multiple reports?!?!?!?
        if len(reports) > 1:
            for report in reports:
                if report:
                    report_prompt = report
                    break

        if len(reports) == 1:
            report_prompt = reports[0]

        if not report_prompt:
            _l.warning(f"🚫 No sanitizer report found")

        for poi in poi_cluster.pois:
            debug_information = ""
            # TODO: add back from dyva maybe?
            #if poi.debug_info:
            #    debug_information = PromptGenerator.render(DEBUG_INFORMATION, {"DEBUG_INFO": poi.debug_info})

            source = self.get_source(poi)
            file_name_and_func_name = f"<File_Name> {poi.function.file_path} </File_Name>\n<Func_Name> {poi.function.name} </Func_Name>\n"
            crash_commit_diff = self._get_crash_commit_diff(poi)
            global_vars, vuln_loc = self._get_code_info(poi)

            if len([poi for poi in poi_cluster.pois]) > 1:
                poi_specific_info = PromptGenerator.render(POI_SPECIFIC_INFO,
                                                           {
                                                               "SOURCE": file_name_and_func_name + source,
                                                           })
            else:
                poi_specific_info = PromptGenerator.render(POI_SPECIFIC_INFO,
                                                           {
                                                               "SOURCE": file_name_and_func_name + source,
                                                               "CRASH_COMMIT_DIFF": crash_commit_diff,
                                                               "VULNERABLE_LOC": vuln_loc,
                                                               "GLOBAL_VARIABLES": global_vars,
                                                               "DEBUG_INFORMATION": debug_information,
                                                           })

            all_poi_info += poi_specific_info
            all_poi_info_summary += f" Function: {poi.function.name} File: {poi.function.file_path}\n"
            all_poi_info_summary += vuln_loc
            all_poi_info_summary += debug_information

        # Infer the bug type and summarize the crash report
        summary_prompt_args = {
            "REPORT": report_prompt,
            "ALL_POI_INFO_SUMMARY": all_poi_info_summary,
        }
        bug_type, cost = self._generate_report_summary(summary_prompt_args)
        bug_type = "According to experts, the vulnerability type is: " + bug_type
        self.cost += cost
        # choose the style of the whole prompt
        singleton_cluster = len(poi_cluster.pois) == 1

        # initial_prompt = THREE_EXPERTS_PROMPT if singleton_cluster else INITIAL_PROMPT
        failed_prompt = THREE_EXPERTS_FAILED_PATCH_PROMPT if singleton_cluster else FAILED_PATCH_PROMPT

        example = ""
        if singleton_cluster:
            example = self._get_rag_example(poi_cluster.pois[0])
        if self._is_java_target():
            format_example = JAVA_FORMAT_EXAMPLE
            _l.info(f"☕ We are patching JAVA!")
        else:
            _l.info(f"🙈 We are patching C!")
            format_example = FORMAT_EXAMPLE
        use_expert_reasoning = True if not singleton_cluster else self.use_expert_reasoning

        prompt_args = {
            "BUG_TYPE": bug_type,
            "REPORT": report_prompt,
            "CRASH_LINE": actual_crash_loc,
            "ALL_POI_INFO": all_poi_info,
            "FORMAT_EXAMPLE": format_example,
            "EXAMPLE": example,
            "use_failed_patch_reasoning": self.use_failed_patch_reasoning,
            "use_failed_patch_code": self.use_failed_patch_code,
            "use_expert_reasoning": use_expert_reasoning,
        }
        patch_prompt = PatchPromptTool(failed_prompt, prompt_args, failed_patch=failed_patch).generate_prompt()
        _l.debug(f"💭 Prompting with prompt len={len(patch_prompt)}")
        _l.debug(f"💭 Prompting with prompt: {patch_prompt}")
        if "claude-3" in self.model:
            original_prompt = [
                {"role": "user", "content": "follow the instruction in the system prompt below"},
                {"role": "system", "content": patch_prompt},
            ]
        else:
            original_prompt = [{"role": "system", "content": patch_prompt}]

        file_func_patchcode = dict()
        for i in range(self._max_regenerate_for_format_error):
            file_func_patchcode, cost, _ = self._generate_patch_in_loop(original_prompt)
            self.cost += cost
            if file_func_patchcode:
                break
            _l.critical("Format error found in the patch")

        return self._parse_patch_from_response(file_func_patchcode, poi_cluster)

    def _get_prompt(self):
        if self.prompt_style == LLMPromptingStyles.ONE_SHOT_EXPERTS:
            initial_prompt = THREE_EXPERTS_PROMPT
            failed_prompt = THREE_EXPERTS_FAILED_PATCH_PROMPT
        else:
            raise ValueError(f"Unsupported prompting style: {self.prompt_style}")
        return failed_prompt, initial_prompt

    def _get_rag_example(self, poi: PoI):
        example = ""
        # if "AICC" in str(self.source_info) and self.source_info.:
        #     FUNC_DIFF = retrieve_example(
        #         self.source_info, self.get_source(poi), vul_description=self.source_info.sanitizer_string
        #     )
        # else:
        #     FUNC_DIFF = retrieve_example(self.source_info, self.get_source(poi))
        # if FUNC_DIFF != "":
        #     example = PromptGenerator.render(FUNC_DIFF, {"FUNC_DIFF": FUNC_DIFF})
        return example

    def _get_code_info(self, poi: PoI):
        # retrive info from code like vulnerable location and global variables
        # FIXME: modify it for multi pois
        vuln_loc = ""
        global_vars = ""
        crash_loc = self.read_crash_loc(poi)
        if crash_loc:
            vuln_loc = PromptGenerator.render(VULNERABLE_LOC, {"CRASH_LOC": crash_loc})
        if poi.function.global_vars:
            global_vars = PromptGenerator.render(GLOBAL_VARIABLES, {"GLOBALS": "\n".join(poi.function.global_vars)})
        return global_vars, vuln_loc

    def _get_crash_commit_diff(self, poi: PoI):
        crash_commit_diff = ""
        if poi.git_diff:
            git_diff = poi.git_diff
            if poi.function.code:
                func_lines = poi.function.code.split("\n")
                git_diff_lines = git_diff.split("\n")
                if len(git_diff_lines) > len(func_lines):
                    _l.warning(
                        f"Git diff is longer than the function source code, truncating it to match the function source code length")
                    git_diff = "\n".join(git_diff_lines[: len(func_lines)])
            crash_commit_diff = PromptGenerator.render(CRASH_COMMIT_DIFF, {"GIT_DIFF": git_diff})

        return crash_commit_diff

    def propose_patch(self, patched_functions: List[PatchedFunction], reasoning=None):
        patch = Patch(
            patched_functions,
            reasoning=reasoning,
        )
        _l.debug(f"💭 Proposed patch: {patch}")
        # cache the real diff
        self.source_info.git_diff(patch)
        _l.info(f"✅ Diff successfully generated:\n{patch.diff}")
        return patch

    def generate_patch(
            self, poi_cluster: PoICluster, reports: Optional[List], failed_patch: Optional[Patch] = None,
            **kwargs
    ) -> Optional[Patch]:
        _l.debug("🔍 Generating patch...")
        _l.debug(f"we are using {self.model}")
        self.cost = 0
        return self._generate_patch_one_shot(poi_cluster, reports, failed_patch=failed_patch, **kwargs)
