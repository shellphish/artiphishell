import logging
import os
import re
import time
import datetime

from typing import List, Dict, Tuple

from kumushi.data import Program
from agentlib import LLMFunction
from ..utils import llm_cost, LLM_MAPPING

_l = logging.getLogger(__name__)



def get_llm_backups(model: str) -> List[str]:
    if model == LLM_MAPPING.get('o4-mini'):
        return [LLM_MAPPING.get('o3-mini'), LLM_MAPPING.get('o3')]
    if model == LLM_MAPPING.get('o3-mini'):
        return [LLM_MAPPING.get('o4-mini'), LLM_MAPPING.get('o3')]
    if model == LLM_MAPPING.get('claude-3.7-sonnet'):
        return [LLM_MAPPING.get('o3-mini'), LLM_MAPPING.get('o4-mini'), LLM_MAPPING.get('gpt-4.1')]
    return [LLM_MAPPING.get('claude-3.7-sonnet'), LLM_MAPPING.get('o4-mini'), LLM_MAPPING.get('gpt-4.1')]

def get_llm_params(model: str, temperature: float, enable_thinking = False) -> Tuple[float, str | None, dict | None]:
    """
    Get the LLM parameters based on the model and temperature.
    Args:
        model (str): The model name.
        temperature (int): The temperature value.
        enable_thinking (bool): Whether to enable thinking.
    Returns:
        Tuple[int, str | None, dict | None]: The temperature, reasoning effort, and think_param.
    """
    temperature = temperature
    reasoning_effort = None
    think_param = None
    if 'o1' in model or 'o3' in model or 'o4' in model:
        temperature = 1.0
        reasoning_effort = 'medium'
        if enable_thinking:
            reasoning_effort = 'high'
    if 'claude-3.7-sonnet' in model and enable_thinking:
        think_param = {"type": "enabled", "budget_tokens": 10000}

    return temperature, reasoning_effort, think_param



def post_llm_requests(messages: List[Dict], temperature: float, model: str, enable_thinking: bool = True) -> Tuple[
    dict, float]:
    reasoning_effort = None

    if os.getenv("LITELLM_KEY"):
        key = os.environ.get("LITELLM_KEY")
    else:
        raise ValueError(f"Missing LLM API KEY")
    if os.getenv("AIXCC_LITELLM_HOSTNAME"):
        query_api = os.environ.get("AIXCC_LITELLM_HOSTNAME")
    else:
        raise ValueError(f"Missing LLM API ENDPOINT URL")
    _l.info(f"🔍 Prompting with temperature: {temperature} and model: {model}")
    if model not in LLM_MAPPING.values():
        _l.warning(f"Unknown model: {model}")
        model = LLM_MAPPING.get('claude-3.7-sonnet')
    user_budget = _get_model_budget(model)
    if user_budget is None:
        raise RuntimeError(f"Unknown model: {model}")
    fallbacks = get_llm_backups(model)
    fallback_index = 0
    send_model = LLM_MAPPING.get(model)
    user_budget = _get_model_budget(model)
    current_llm_cost = 0
    response = None
    system_prompt = "This is the system prompt! "
    user_prompt = "This is the user prompt! "
    for message in messages:
        if message['role'] == 'system':
            system_prompt += message['content']
        elif message['role'] == 'user':
            user_prompt += message['content']

    while True:
        # TODO: put manual fallback calculation here
        try:
            adj_temperature, reasoning_effort, thinking_param = get_llm_params(send_model, temperature, enable_thinking)
            if thinking_param:
                llm = LLMFunction.create(
                    system_prompt,
                    user_prompt,
                    output='text',
                    model=send_model,
                    use_logging=False,
                    retries=3,
                    include_usage=True,
                    temperature=adj_temperature,
                    thinking=thinking_param,
                )
            elif reasoning_effort:
                llm = LLMFunction.create(
                    system_prompt,
                    user_prompt,
                    output='text',
                    model=send_model,
                    use_logging=True,
                    retries=3,
                    include_usage=True,
                    temperature=adj_temperature,
                    reasoning_effort=reasoning_effort
                )
            else:
                llm = LLMFunction.create(
                    system_prompt,
                    user_prompt,
                    output='text',
                    model=send_model,
                    use_logging=True,
                    retries=3,
                    include_usage=True,
                    temperature=adj_temperature
                )
            response, usage = llm()
            _l.info(f"money used is {usage.get_costs(send_model)}")
            current_llm_cost = usage.get_costs(send_model)['total_cost']
            # response = completion(
            #     model=send_model, messages=messages, api_key=key, base_url=query_api,
            #     temperature=adj_temperature, num_retries=3, timeout=30, user=user_budget,
            #     reasoning_effort=reasoning_effort, drop_params=True,
            #     # thinking=thinking_param,
            # )
            break
        except Exception as e:
            current_minute = datetime.datetime.now().minute
            if current_minute % 30 == 0:
                _l.info(f"Budget reset per 30 mins, retry it")
                continue
            if fallback_index >= len(fallbacks):
                _l.critical(f"Failed to connect to LLM: {e}")
                fallback_index = 0
                send_model = model
                time.sleep(30)
                continue
            send_model = fallbacks[fallback_index]
            _l.info(f"trying {send_model} instead")
            time.sleep(30)
            fallback_index += 1

    llm_response = response
    _l.info("LLM response received successfully.")
    # current_llm_cost = completion_cost(llm_response)
    # if 'additional_headers' not in response._hidden_params or 'llm_provider-x-litellm-response-cost' not in response._hidden_params['additional_headers']:
    #     _l.warning("No LLM cost found in response headers, using default cost of 0.0")
    #     current_llm_cost = 0.0
    # else:
    #     current_llm_cost = float(response._hidden_params['additional_headers']['llm_provider-x-litellm-response-cost'])
    actual_model = send_model
    _l.info(f"💸 LLM cost: {current_llm_cost} and the model we actually use: {actual_model}")
    if llm_response is None:
        return {}, 0.0
    return llm_response, current_llm_cost


def _get_model_budget(model: str) -> str | None:
    budget = None
    if os.environ.get("ARTIPHISHELL_GLOBAL_ENV_IS_CI_LLM_BUDGET", None) == 'true':
        budget = 'patching-budget'
    else:
        if 'oai' in model or 'gpt' in model:
            budget = 'openai-budget'
        elif 'claude' in model:
            budget = 'claude-budget'
        elif 'gemini' in model:
            budget = 'gemini-budget'
    return budget


def parse_llm_output(response, model: str) -> str:
    # output = response["choices"][0]["message"]
    # content = output["content"]
    # completion_tokens = response["usage"]["completion_tokens"]
    # prompt_tokens = response["usage"]["prompt_tokens"]
    # # cached_prompt_tokens = response["usage"]["prompt_tokens_details"]["cached_tokens"]
    # cached_prompt_tokens = response["usage"].get("cache_read_input_tokens", 0)
    # _l.info(f"llm cost is {llm_cost(model, prompt_tokens, completion_tokens, cached_prompt_tokens)}")
    _l.debug(f"output content is {response}")
    return response


def parse_search_patch(patch_text):
    # Split the text into file/function blocks
    file_function_blocks = re.split(r'\n(?=File: )', patch_text.strip())
    patches = []
    for block in file_function_blocks:
        if not block.strip():
            continue
        # Extract the file name and function name
        file_function_match = re.match(r'File:\s+(.*?)\s+-\s+([a-zA-Z0-9_]+)\(?', block)
        if not file_function_match:
            _l.debug(f"Failed to parse file and function from block:\n{block}")
            continue
        file_name = str(file_function_match.group(1).strip())
        function_name = str(file_function_match.group(2).strip())

        # Extract all code blocks associated with this function
        code_blocks = re.findall(r'```(.*?)```', block, re.DOTALL)
        search_replace_pairs = []
        for code_block in code_blocks:
            # Parse the search and replace code blocks
            code_pattern = r'<<<<<<< SEARCH\n(.*?)\n=======\n(.*?)\n>>>>>>> REPLACE'
            code_match = re.search(code_pattern, code_block, re.DOTALL)
            if code_match:
                search_code = str(code_match.group(1).rstrip())
                replace_code = str(code_match.group(2).rstrip())
                search_replace_pairs.append({
                    'search_code': search_code,
                    'replace_code': replace_code
                })
            else:
                _l.debug(f"Failed to parse code block for function {function_name} in file {file_name}")
        if search_replace_pairs:
            patches.append({
                'file_name': file_name,
                'function_name': function_name,
                'search_replace_pairs': search_replace_pairs
            })
    return patches


def replace_search_patch(function_code, search_code, replace_code):
    function_lines = function_code.splitlines()
    search_lines = search_code.splitlines()
    replace_lines = replace_code.splitlines()

    # Normalize lines by stripping leading/trailing whitespace
    function_lines_stripped = [line.strip() for line in function_lines]
    search_lines_stripped = [line.strip() for line in search_lines]
    # Search for the sequence search_lines_stripped in function_lines_stripped
    found = False
    for i in range(len(function_lines_stripped) - len(search_lines_stripped) + 1):
        match = True
        for j in range(len(search_lines_stripped)):
            if function_lines_stripped[i + j] != search_lines_stripped[j]:
                match = False
                break
        if match:
            # Track indentation preservation# Keep track of which replace lines have been processed
            processed_indices = set()
            # Map each search line to its corresponding replace line
            for s_i, s_line in enumerate(search_lines):
                s_indent = len(s_line) - len(s_line.lstrip())
                for r_i, r_line in enumerate(replace_lines):
                    # Only consider lines that haven't been processed yet
                    if r_i not in processed_indices and s_line.strip() == r_line.strip():
                        replace_lines[r_i] = ' ' * s_indent + r_line.strip()
                        processed_indices.add(r_i)
                        break
            found = True
            # Replace the lines
            function_lines = function_lines[:i] + replace_lines + function_lines[i + len(search_lines):]
            break  # Break after first replacement for this search-replace pair
    if not found:
        _l.debug("Search code not found in function.")
        return ''
    return '\n'.join(function_lines)
