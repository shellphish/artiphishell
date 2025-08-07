from difflib import unified_diff
from typing import Optional, List, Dict

import logging
import json
import requests
import os
import numpy as np
import sys
import time
import re
import random

from ..data import ProgramInfo, Patch, ProgramPOI, AICCProgramInfo
from ..code_parsing.code_parser import CodeParser
from .llm_prompting_styles import LLMPromptingStyles
from ..utils import llm_cost
from .prompts.one_shot_prompts import (
    EXAMPLE,
    RAG_EXAMPLE,
    THREE_EXPERTS_PROMPT,
    THREE_EXPERTS_FAILED_PATCH_PROMPT,
    INITIAL_PROMPT,
    FAILED_PATCH_PROMPT,
    CRASH_COMMIT_DIFF,
    VULNERABLE_LOC,
    GLOBAL_VARIABLES,
    FORMAT_EXAMPLE,
    DEBUG_INFORMATION,
    JAVA_FORMAT_EXAMPLE
)

from sklearn.metrics.pairwise import cosine_similarity
from jinja2 import StrictUndefined, Template

_l = logging.getLogger(__name__)


class LLMPatchGenerator:
    def __init__(
        self,
        source_info: ProgramInfo,
        prompt_style: Optional[LLMPromptingStyles] = None,
        use_failed_patch_code: bool = False,
        use_failed_patch_reasoning: bool = True,
        use_expert_reasoning: bool = True,
    ):

        self.model = "oai-gpt-4o"
        _l.debug(f"🔍 Using model: {self.model}")
        self.source_info = source_info

        self._many_shot = False
        self._experts = False
        self.prompt_style = prompt_style
        self._resolve_prompt_style()

        self.cost = 0.0
        self.retry_conn = 5
        self.temperature = 0.0
        self.use_failed_patch_code = use_failed_patch_code
        self.use_failed_patch_reasoning = use_failed_patch_reasoning
        self.use_expert_reasoning = use_expert_reasoning

        self.messages = []

    def _resolve_prompt_style(self):
        if self.prompt_style is None:
            is_many_shot = False
            use_experts = True

            if is_many_shot:
                if use_experts:
                    self.prompt_style = LLMPromptingStyles.CHAIN_OF_THOUGHTS_EXPERTS
                else:
                    self.prompt_style = LLMPromptingStyles.CHAIN_OF_THOUGHTS
            else:
                if use_experts:
                    self._experts = True
                    self.prompt_style = LLMPromptingStyles.ONE_SHOT_EXPERTS
                else:
                    self.prompt_style = LLMPromptingStyles.ONE_SHOT

        _l.debug(f"We are enabling three experts prompt, {self.prompt_style}")

        if (
            self.prompt_style == LLMPromptingStyles.CHAIN_OF_THOUGHTS
            or self.prompt_style == LLMPromptingStyles.CHAIN_OF_THOUGHTS_EXPERTS
        ):
            self._many_shot = True
        else:
            self._many_shot = False

    def append_message(self, msg):
        self.messages.append(msg)

    def get_source(self, poi: ProgramPOI) -> str:
        if poi.func_src:
            function_src = poi.func_src + "\n"
            # this means the source is corrupted, we need to try get it out self
            if "\\n" in function_src:
                if poi.func_startline is not None and poi.func_endline is not None and poi.file.exists():
                    with open(poi.file, "r") as f:
                        lines = f.readlines()
                        function_src = "".join(lines[poi.func_startline - 1 : poi.func_endline])
                else:
                    _l.error("It's likley that the function source parsing is corruped for %s", poi)
            return function_src
        else:
            funcparse = CodeParser(poi.file, lang=self.source_info.lang)
            return "".join(funcparse.func_code(poi.function)) + "\n"

    def get_embeddings(self, text: str) -> np.ndarray:
        if os.getenv("EMBEDDING_API"):
            api_url = os.environ.get("EMBEDDING_API")
        else:
            raise ValueError(f"Missing EMBEDDING API")
        endpoint_url = f"{api_url}/embed"
        model = "oai-text-embedding-3-small"
        auth_key = "!!Shellphish!!"
        try:
            response = requests.post(
                endpoint_url, json={"text": text, "model": model, "auth_key": auth_key}, timeout=30
            )
        except requests.exceptions.Timeout:
            _l.warning(f"embedding api time out")
            return None
        if response.status_code != 200:
            _l.debug(f"Embeddings URL failed, code: {response.status_code}")
            return None
        else:
            results = response.json()
            if "embedding" not in results:
                return None
            embeddings = np.asarray(results["embedding"])

            return embeddings
    def retrieve_example(self, source: str, vul_description: str = None) -> str:
        if self.source_info.lang.lower() == "java":
            knowledge_base = "Jenkins"
        elif not self.source_info.is_kernel:
            knowledge_base = "Generic_C"
        else:
            knowledge_base = "Kernel"
        _l.info(f"🔍 Using knowledge base {knowledge_base}")
        try:
            if os.getenv("RETRIEVAL_API"):
                api_url = os.environ.get("RETRIEVAL_API")
            else:
                raise ValueError("Missing RETRIEVAL API")
            endpoint_url = f"{api_url}/api/funcs/closest_vuln"
            res = requests.post(
                endpoint_url,
                json={
                    "query": source,  # vulnerable function's source code goes there
                    "num_return": 15,  # how many similar functions you're retrieving
                    "auth_key": "!!Shellphish!!",
                    "knowledge_base": knowledge_base,  # to query the Kernel knowledge base
                },
                timeout=30
            )
            # _l.debug(f'vul_description: {vul_description}')
            if res.status_code != 200:
                _l.debug(f"Retrival URL failed, code: {res.status_code}")
            res = res.json()
            if vul_description is not None and vul_description != "":
                _l.debug(f"🔍 Ranking examples by similarity to the vul_description: {vul_description}")
                orig_description_embedding = self.get_embeddings(vul_description)
                if orig_description_embedding is None:
                    func_diff = unified_diff(
                        res["result"][0]["code_vulnerable"].split("\n"),
                        res["result"][0]["code_patched"].split("\n"),
                        fromfile="vulnerable",
                        tofile="patched",
                    )
                    return "\n".join(func_diff)
                results = res["result"]
                for result in results:
                    result_embedding = result["vulnerability_description_embedding"]
                    result["cosine_similarity"] = cosine_similarity([orig_description_embedding], [result_embedding])[0][0]
                    # _l.debug(f"cosine_similarity: {result['cosine_similarity']}")
                    # _l.debug(result['vulnerability_description'])
                sorted_results = sorted(results, key=lambda x: x["cosine_similarity"], reverse=True)
                res["result"] = sorted_results
            func_diff = unified_diff(
                res["result"][0]["code_vulnerable"].split("\n"),
                res["result"][0]["code_patched"].split("\n"),
                fromfile="vulnerable",
                tofile="patched",
            )
            return "\n".join(func_diff)
        except Exception:
            _l.warning("Failed to generate a patch example. Return \"no example\" instead.", exc_info=True)
            return ""

    def propose_patch(self, poi: ProgramPOI, new_code, old_code, reasoning=None):
        patch = Patch(
            poi,
            new_code,
            old_code=old_code,
            reasoning=reasoning,
        )
        _l.info(f"💭 Proposed patch: {patch}")
        # cache the real diff
        self.source_info.git_diff(patch)
        _l.info(f"✅  Diff successfully generated:\n{patch.diff}")
        return patch

    def generate_patch(
        self, poi: ProgramPOI, report, failed_patch: Optional[Patch] = None, **kwargs
    ) -> Optional[Patch]:
        _l.debug("🔍 Generating patch...")
        _l.debug(f"we are using {self.model}")
        self.cost = 0
        if self._many_shot:
            raise NotImplementedError("Many-shot prompting was deprecated. Do not use this!")
        else:
            patch_func = self._generate_patch_one_shot

        return patch_func(poi, report, failed_patch=failed_patch, **kwargs)

    #
    # Prompting styles
    #
    @staticmethod
    def read_crash_loc(poi: ProgramPOI) -> Optional[str]:
        func_line_len = 0
        if poi.func_startline and poi.func_endline:
            func_line_len = poi.func_endline - poi.func_startline
        else:
            _l.warning(f"🚫 Missing function start or end line information")
            return None
        if func_line_len < 50:
            return None
        if poi.lineno:
            loc_prompt = (
                f"Here is the exact crash line in function {poi.function} at line {poi.lineno} of the file {poi.file}:\n\n"
                f"{poi.linetext}\n"
            )
            return loc_prompt
        return None
    
    @staticmethod
    def read_invariant_loc(poi: ProgramPOI) -> Optional[str]:
        line_offset = 0
        func_line_len = 0
        if poi.func_startline and poi.func_endline:
            line_offset = poi.lineno - poi.func_startline
            func_line_len = poi.func_endline - poi.func_startline
        else:
            _l.warning(f"🚫 Missing function start or end line information")
            return None
        if line_offset > func_line_len:
            _l.warning(f"🚫 line number does not find in function")
            return None
        code_lines = poi.func_src.split("\n")
        invariant_line = code_lines[line_offset].strip()
        return str(invariant_line)

    def _parse_patch_from_response(self, response: str, poi, source, reasoning=None) -> Optional[Patch]:
        new_code = response
        if poi.function not in new_code:
            _l.critical(f"🚫 The proposed patch does not contain the target function {poi.function}")
            return None
        return self.propose_patch(poi, new_code, source, reasoning=reasoning)

    def _retry_requests_connection(self, query_endpoint, query_headers, query_payload):
        #FIXME: This is a temporary fix for the connection error
        while True:
            try:
                response = requests.post(query_endpoint, headers=query_headers, data=query_payload)
            except requests.exceptions.ConnectionError as e:
                _l.critical(f"connection error: {e}. Retrying.")
                time.sleep(random.uniform(1.0,5.0))
                continue
            if response.status_code != 200:
                try:
                    data = response.json()
                    error_message = data.get("error", {}).get("message", None)
                    if "Budget has been exceeded!" in error_message:
                        _l.warning(f"Budget has been exceeded! EXITING.")
                        sys.exit(1)
                    if (
                        "No deployments available for selected model" in error_message
                        or "RateLimitError" in error_message
                    ):
                        _l.warning(f"Rate limited, retrying after 60 seconds.")
                        time.sleep(60)
                        continue
                except Exception:
                    _l.critical(
                        "Unexpected error during retry_requests_connection(). Sleep 30 seconds before retrying.",
                        exc_info=True,
                    )
                    time.sleep(30)
                    _l.critical("Slept 30 seconds after an unexpected error. Retry.")
                    continue
            else:
                return response.json()
        # _l.critical(f"we tried reconnect to {query_endpoint} {self.retry_conn} times and all failed. Bailing!")

    def _post_llm_requests(self, messages: List[Dict]):
        if os.getenv("LITELLM_KEY"):
            key = os.environ.get("LITELLM_KEY")
        else:
            raise ValueError(f"Missing LLM API KEY")
        if os.getenv("AIXCC_LITELLM_HOSTNAME"):
            query_api = os.environ.get("AIXCC_LITELLM_HOSTNAME")
        else:
            raise ValueError(f"Missing LLM API ENDPOINT URL")
        query_endpoint = f"{query_api}/chat/completions"
        query_headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
        _l.debug(f"🔍 Prompting with temperature: {self.temperature}")
        query_payload = json.dumps(
            {
                "messages": messages,
                "model": self.model,
                "temperature": self.temperature,
            }
        )

        return self._retry_requests_connection(query_endpoint, query_headers, query_payload)

    def _generate_patch_in_loop(self, original_prompt):
        cost = 0.0
        response = self._post_llm_requests(original_prompt)
        current_patch = ""
        output = response["choices"][0]["message"]
        content = output["content"]
        completion_tokens = response["usage"]["completion_tokens"]
        prompt_tokens = response["usage"]["prompt_tokens"]
        cost += llm_cost(self.model, prompt_tokens, completion_tokens)
        _l.debug(f"output content is {content}")
        # GPT would return like c```patch code`` or java ```patch code```, this is ONLY true for GPT
        
        # start_pos = content.find("```")
        # if start_pos > 0:
        #     content = content[start_pos:]
        # end_pos = content.rfind("```")
        # if end_pos > 0:
        #     content = content[:end_pos]
        # content = content.replace("```", "")
        # lines = content.split("\n")[1:]
        # last_line = lines[-1]
        # lines = lines[:-1]
        # new_content = "\n".join(lines)
        # current_patch += new_content
        
        header_pattern = r"```(cpp|c|java)"
        tail_patter = r"```"
        head_position = None
        tail_position = None
        # Find all matches
        header_matches = list(re.finditer(header_pattern, content))
        tail_matches = list(re.finditer(tail_patter, content))
        
        # Get the positions of each match
        if len(header_matches) > 0:
            head_position = list(header_matches)[-1].end()
        if len(tail_matches) > 0:
            tail_position = list(tail_matches)[-1].start()
        
        if head_position is not None:
            if tail_position is not None:
                current_patch = content[head_position:tail_position] + "\n"
            else:
                current_patch = content[head_position:] + "\n"
        
        count = 0
        finish_reason = response["choices"][0]["finish_reason"]
        while finish_reason == "length":
            _l.debug(f"continue generation")
            new_content = ""
            head_position = None
            tail_position = None
            count += 1
            assistant_prompt = {"role": "assistant", "content": f"{current_patch}"}
            continue_generation_prompt = {"role": "system", "content": "continue generating"}
            original_prompt.append(assistant_prompt)
            original_prompt.append(continue_generation_prompt)
            response = self._post_llm_requests(original_prompt)  # this should be 0.0 for continuation
            output = response["choices"][0]["message"]
            content = output["content"]
            completion_tokens = response["usage"]["completion_tokens"]
            prompt_tokens = response["usage"]["prompt_tokens"]
            _l.debug(f"prompt use {prompt_tokens} prompts tokens and {completion_tokens} completion_tokens")
            cost += llm_cost(self.model, prompt_tokens, completion_tokens)
            # llm would return like c```patch code`` or java ```patch code```
            # Find all matches
            header_matches = list(re.finditer(header_pattern, content))
            tail_matches = list(re.finditer(tail_patter, content))
            
            # Get the positions of each match
            if len(header_matches) > 0:
                head_position = list(header_matches)[-1].end()
            if len(tail_matches) > 0:
                tail_position = list(tail_matches)[-1].start()

            if head_position is not None:
                if tail_position is not None:
                    new_content = content[head_position:tail_position] + "\n"
                else:
                    new_content = content[head_position:] + "\n"
            else:
                if tail_position is not None:
                    new_content = content[:tail_position] + "\n"
            current_patch += new_content
            finish_reason = response["choices"][0]["finish_reason"]
        final_patch = current_patch + "\n" 
        return final_patch, cost
    def _is_java_target(self):
        return self.source_info.lang.lower() == "java"
    
    def _generate_patch_one_shot(
        self, poi: ProgramPOI, report, failed_patch: Optional[Patch] = None, **kwargs
    ) -> Optional[Patch]:

        crash_commit_diff = ""
        if poi.git_diff:
            git_diff = poi.git_diff
            if poi.func_src:
                func_lines = poi.func_src.split("\n")
                git_diff_lines = git_diff.split("\n")
                if len(git_diff_lines) > len(func_lines):
                    _l.warning(f"Git diff is longer than the function source code, truncating it to match the function source code length")
                    git_diff = "\n".join(git_diff_lines[: len(func_lines)])

            diff_template = Template(CRASH_COMMIT_DIFF, undefined=StrictUndefined)
            diff_template_args = {"GIT_DIFF": git_diff}
            crash_commit_diff = diff_template.render(diff_template_args)

        debug_information = ""
        format_example = ""
        if self._is_java_target():
            format_example = JAVA_FORMAT_EXAMPLE
            _l.info(f"☕ We are patching JAVA!")
        else:
            _l.info(f"🙈 We are patching C!")
            format_example = FORMAT_EXAMPLE
            if poi.debug_info:
                DEBUG_INFO = poi.debug_info
                debug_template = Template(DEBUG_INFORMATION, undefined=StrictUndefined)
                debug_template_args = {"DEBUG_INFO": DEBUG_INFO}
                debug_information = debug_template.render(debug_template_args)

        if self._experts:
            initial_prompt = THREE_EXPERTS_PROMPT
            failed_prompt = THREE_EXPERTS_FAILED_PATCH_PROMPT
        else:
            initial_prompt = INITIAL_PROMPT
            failed_prompt = FAILED_PATCH_PROMPT

        crash_loc = self.read_crash_loc(poi)
        vuln_loc = ""
        if crash_loc:
            CRASH_LOC = crash_loc
            vuln_loc_template = Template(VULNERABLE_LOC, undefined=StrictUndefined)
            vuln_loc_template_args = {"CRASH_LOC": CRASH_LOC}
            vuln_loc = vuln_loc_template.render(vuln_loc_template_args)

        global_vars = ""
        if poi.global_variables:
            global_variables_template = Template(GLOBAL_VARIABLES, undefined=StrictUndefined)
            global_variables_template_args = {"GLOBALS": "\n".join(poi.global_variables)}
            global_vars = global_variables_template.render(global_variables_template_args)

        source = self.get_source(poi)

        example = ""
        if isinstance(self.source_info, AICCProgramInfo) and self.source_info.sanitizer_string:
            FUNC_DIFF = self.retrieve_example(self.get_source(poi), self.source_info.sanitizer_string)
        else:
            FUNC_DIFF = self.retrieve_example(self.get_source(poi))

        if FUNC_DIFF != "":
            example_template = Template(RAG_EXAMPLE, undefined=StrictUndefined)
            example_template_args = {"FUNC_DIFF": FUNC_DIFF}
            example = example_template.render(example_template_args)
            # _l.debug(f"🔍 Example retrieved from knowledge base: {example}")

        if failed_patch is None or (not self.use_failed_patch_reasoning and not self.use_failed_patch_code):
            prompt = initial_prompt
            prompt_args = {
                "REPORT": report,
                "SOURCE": source,
                "FORMAT_EXAMPLE": format_example,
                "EXAMPLE": example,
                "CRASH_COMMIT_DIFF": crash_commit_diff,
                "VULNERABLE_LOC": vuln_loc,
                "GLOBAL_VARIABLES": global_vars,
                "DEBUG_INFORMATION": debug_information,
                "use_expert_reasoning": self.use_expert_reasoning,
            }
        else:
            prompt = failed_prompt
            prompt_args = {
                "REPORT": report,
                "SOURCE": source,
                "FORMAT_EXAMPLE": format_example,
                "WRONG_PATCH": failed_patch.new_code,
                "REASONING": failed_patch.reasoning,
                "EXAMPLE": example,
                "CRASH_COMMIT_DIFF": crash_commit_diff,
                "VULNERABLE_LOC": vuln_loc,
                "GLOBAL_VARIABLES": global_vars,
                "DEBUG_INFORMATION": debug_information,
                "use_failed_patch_reasoning": self.use_failed_patch_reasoning,
                "use_failed_patch_code": self.use_failed_patch_code,
                "use_expert_reasoning": self.use_expert_reasoning,
            }
        debug_prompt_template = Template(prompt, undefined=StrictUndefined)
        debug_prompt = debug_prompt_template.render(prompt_args)
        _l.debug(f"💭 Prompting with prompt len={len(debug_prompt)}")
        _l.info(f"💭 Prompting with prompt: {debug_prompt}")
        if "claude-3" in self.model:
            original_prompt = [
                {"role": "user", "content": "follow the instruction in the system prompt below"},
                {"role": "system", "content": debug_prompt},
            ]
        else:
            original_prompt = [{"role": "system", "content": debug_prompt}]

        final_patch, self.cost = self._generate_patch_in_loop(original_prompt)

        return self._parse_patch_from_response(final_patch, poi, source)
