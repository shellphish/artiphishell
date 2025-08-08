"""
Helper util for handling openai-specific cost calculation
- e.g.: prompt caching
"""

import sys
from typing import Literal, Optional, Tuple

from litellm._logging import verbose_logger
from litellm.types.utils import CallTypes, Usage
from litellm.utils import get_model_info


def cost_router(call_type: CallTypes) -> Literal["cost_per_token", "cost_per_second"]:
    if call_type == CallTypes.atranscription or call_type == CallTypes.transcription:
        return "cost_per_second"
    else:
        return "cost_per_token"

def calculate_costs_agentlib(
    model: str,
    prompt_tokens: int,
    completion_tokens: int,
    cache_creation_input_tokens: int = 0,
    cache_read_input_tokens: int = 0,
):
    if model is None:
        return dict(
            prompt_cost=0,
            completion_cost=0,
            total_cost=0,
            tcpm=0,
        )

    # 0.0001
    per_t_in = 0
    per_t_out = 0

    prompt_cost = 0
    completion_cost = 0

    per_t_in_cache_read = None
    per_t_in_cache_write = None

    if "o4-mini" in model:
        per_t_in = 1.10
        per_t_out = 4.40
        per_t_in_cache_read = 0.275
    elif "o3-mini" in model:
        per_t_in = 1.10
        per_t_out = 4.40
        per_t_in_cache_read = 0.55
    elif "o3" in model:
        per_t_in = 2
        per_t_out = 8
        per_t_in_cache_read = 0.5
    elif "o1-preview" in model:
        per_t_in = 15
        per_t_out = 60
        per_t_in_cache_read = 7.5
    elif "o1-mini" in model:
        per_t_in = 1.10
        per_t_out = 4.40
        per_t_in_cache_read = 0.55
    elif "o1" in model:
        per_t_in = 15
        per_t_out = 60
        per_t_in_cache_read = 7.5
    elif "gpt-4-turbo" in model:
        per_t_in = 10
        per_t_out = 30
    elif "gpt-4.1-nano" in model:
        per_t_in = 0.10
        per_t_out = 0.40
        per_t_in_cache_read = 0.025
    elif "gpt-4.1-mini" in model:
        per_t_in = 0.4
        per_t_out = 1.6
        per_t_in_cache_read = 0.10
    elif "gpt-4.1" in model:
        per_t_in = 2
        per_t_out = 8
        per_t_in_cache_read = 0.5
    elif "gpt-4o-mini" in model:
        per_t_in = 0.15
        per_t_out = 0.6
        per_t_in_cache_read = 0.075
    elif "gpt-4o" in model:
        if '05-13' in model:
            per_t_in = 5
            per_t_out = 15
            per_t_in_cache_read = 0
        else:
            per_t_in = 2.5
            per_t_out = 10
            per_t_in_cache_read = 1.25
    elif "gpt-4" in model:
        per_t_in = 30
        per_t_out = 60
    elif "gpt-3.5-turbo" in model or "gpt-3-5-turbo" in model:
        per_t_in = 1
        per_t_out = 2
    elif "claude-4-opus" in model or "claude-opus-4" in model:
        per_t_in = 15
        per_t_out = 75
        per_t_in_cache_read = 1.5
        per_t_in_cache_write = 18.75
    elif "claude-4-sonnet" in model or "claude-sonnet-4" in model:
        per_t_in = 3
        per_t_out = 15
        per_t_in_cache_read = 0.3
        per_t_in_cache_write = 3.75
    elif "claude-3.7-sonnet" in model or "claude-3-7-sonnet" in model:
        per_t_in = 3
        per_t_out = 15
        per_t_in_cache_read = 0.3
        per_t_in_cache_write = 3.75
    elif "claude-3.5-sonnet" in model or "claude-3-5-sonnet" in model:
        per_t_in = 3
        per_t_out = 15
        per_t_in_cache_read = 0.3
        per_t_in_cache_write = 3.75
    elif "claude-3-opus" in model:
        per_t_in = 15
        per_t_out = 75
        per_t_in_cache_read = 1.5
        per_t_in_cache_write = 18.75
    elif "claude-3-sonnet" in model:
        per_t_in = 3
        per_t_out = 15
        per_t_in_cache_read = 0.3
        per_t_in_cache_write = 3.75
    elif "claude-3.5-haiku" in model:
        per_t_in = 0.8
        per_t_out = 3.2
        per_t_in_cache_read = 0.08
        per_t_in_cache_write = 1
    elif "claude-3-haiku" in model:
        per_t_in = 0.25
        per_t_out = 1.25
        per_t_in_cache_read = 0.03
        per_t_in_cache_write = 0.3

    # https://ai.google.dev/gemini-api/docs/pricing
    elif "gemini-2.5-pro" in model:
        if prompt_tokens > 200000:
            per_t_in = 2.5
            per_t_out = 15
            per_t_in_cache_read = 0.625
        else:
            per_t_in = 1.25
            per_t_out = 10
            per_t_in_cache_read = 0.31

    elif "gemini-2.0-flash-lite" in model:
        per_t_in = 0.075
        per_t_out = 0.30
    elif "gemini-2.0-flash" in model:
        per_t_in = 0.10
        per_t_out = 0.40
    elif "gemini-1.5-flash-8b" in model:
        if prompt_tokens > 128000:
            per_t_in = 0.075
            per_t_out = 0.30
        else:
            per_t_in = 0.0375
            per_t_out = 0.15
    elif "gemini-1.5-flash" in model:
        if prompt_tokens > 128000:
            per_t_in = 0.15
            per_t_out = 0.60
        else:
            per_t_in = 0.075
            per_t_out = 0.30
    elif "gemini-1.5-pro" in model:
        if prompt_tokens > 128000:
            per_t_in = 2.50
            per_t_out = 10
        else:
            per_t_in = 1.25
            per_t_out = 5.00

    else:
        pass

    if cache_creation_input_tokens:
        prompt_tokens -= cache_creation_input_tokens
        prompt_cost += cache_creation_input_tokens * per_t_in_cache_write

    if cache_read_input_tokens:
        prompt_tokens -= cache_read_input_tokens
        prompt_cost += cache_read_input_tokens * per_t_in_cache_read

    prompt_cost += prompt_tokens * per_t_in
    completion_cost += completion_tokens * per_t_out

    total_cost = prompt_cost + completion_cost

    m = 1 / 1000000  # per million tokens

    return dict(
        prompt_cost=prompt_cost * m,
        completion_cost=completion_cost * m,
        total_cost=total_cost * m,
        tcpm=total_cost,
    )

def cost_per_token(model: str, usage: Usage) -> Tuple[float, float]:
    """
    Calculates the cost per token for a given model, prompt tokens, and completion tokens.

    Input:
        - model: str, the model name without provider prefix
        - usage: LiteLLM Usage block, containing anthropic caching information

    Returns:
        Tuple[float, float] - prompt_cost_in_usd, completion_cost_in_usd
    """
    ## GET MODEL INFO
    model_info = get_model_info(model=model, custom_llm_provider="openai")
    ## CALCULATE INPUT COST
    ### Non-cached text tokens
    non_cached_text_tokens = usage.prompt_tokens
    cached_tokens: Optional[int] = None
    if usage.prompt_tokens_details and usage.prompt_tokens_details.cached_tokens:
        cached_tokens = usage.prompt_tokens_details.cached_tokens
        non_cached_text_tokens = non_cached_text_tokens - cached_tokens
    prompt_cost: float = non_cached_text_tokens * model_info["input_cost_per_token"]
    ## Prompt Caching cost calculation
    if model_info.get("cache_read_input_token_cost") is not None and cached_tokens:
        # Note: We read ._cache_read_input_tokens from the Usage - since cost_calculator.py standardizes the cache read tokens on usage._cache_read_input_tokens
        prompt_cost += cached_tokens * (
            model_info.get("cache_read_input_token_cost", 0) or 0
        )

    _audio_tokens: Optional[int] = (
        usage.prompt_tokens_details.audio_tokens
        if usage.prompt_tokens_details is not None
        else None
    )
    _audio_cost_per_token: Optional[float] = model_info.get(
        "input_cost_per_audio_token"
    )
    if _audio_tokens is not None and _audio_cost_per_token is not None:
        audio_cost: float = _audio_tokens * _audio_cost_per_token
        prompt_cost += audio_cost

    ## CALCULATE OUTPUT COST
    completion_cost: float = (
        usage["completion_tokens"] * model_info["output_cost_per_token"]
    )
    _output_cost_per_audio_token: Optional[float] = model_info.get(
        "output_cost_per_audio_token"
    )
    _output_audio_tokens: Optional[int] = (
        usage.completion_tokens_details.audio_tokens
        if usage.completion_tokens_details is not None
        else None
    )
    if _output_cost_per_audio_token is not None and _output_audio_tokens is not None:
        audio_cost = _output_audio_tokens * _output_cost_per_audio_token
        completion_cost += audio_cost
    
    try:
        expected_cost = calculate_costs_agentlib(
            model=model,
            prompt_tokens=usage.prompt_tokens,
            completion_tokens=usage["completion_tokens"],
            cache_creation_input_tokens=0,
            cache_read_input_tokens=usage.prompt_tokens_details.cached_tokens,
        )

        import datetime
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

        print(f"""
[{timestamp}] =============== COST PER TOKEN for {model} ===============")
usage: {usage}
non_cached_text_tokens: {non_cached_text_tokens}
cache_hit_tokens: {cached_tokens}
completion_tokens: {usage["completion_tokens"]}
---
p_t_costs: [in:{model_info["input_cost_per_token"]}, cr:{model_info.get("cache_read_input_token_cost")}, cw:0, out:{model_info["output_cost_per_token"]}]
---
prompt_cost: {prompt_cost}
completion_cost: {completion_cost}
---
expected_prompt_cost: {expected_cost["prompt_cost"]}
expected_completion_cost: {expected_cost["completion_cost"]}
""")
        sys.stdout.flush()

        if abs(expected_cost["prompt_cost"] - prompt_cost) > 0.00001:
            print("BAD prompt_cost mismatch!!!")
            sys.stdout.flush()
        if abs(expected_cost["completion_cost"] - completion_cost) > 0.00001:
            print("BAD completion_cost mismatch!!!")
            sys.stdout.flush()
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"Error calculating costs for {model}: {e}")
        sys.stdout.flush()

    return prompt_cost, completion_cost


def cost_per_second(
    model: str, custom_llm_provider: Optional[str], duration: float = 0.0
) -> Tuple[float, float]:
    """
    Calculates the cost per second for a given model, prompt tokens, and completion tokens.

    Input:
        - model: str, the model name without provider prefix
        - custom_llm_provider: str, the custom llm provider
        - duration: float, the duration of the response in seconds

    Returns:
        Tuple[float, float] - prompt_cost_in_usd, completion_cost_in_usd
    """
    ## GET MODEL INFO
    model_info = get_model_info(
        model=model, custom_llm_provider=custom_llm_provider or "openai"
    )
    prompt_cost = 0.0
    completion_cost = 0.0
    ## Speech / Audio cost calculation
    if (
        "output_cost_per_second" in model_info
        and model_info["output_cost_per_second"] is not None
    ):
        verbose_logger.debug(
            f"For model={model} - output_cost_per_second: {model_info.get('output_cost_per_second')}; duration: {duration}"
        )
        ## COST PER SECOND ##
        completion_cost = model_info["output_cost_per_second"] * duration
    elif (
        "input_cost_per_second" in model_info
        and model_info["input_cost_per_second"] is not None
    ):
        verbose_logger.debug(
            f"For model={model} - input_cost_per_second: {model_info.get('input_cost_per_second')}; duration: {duration}"
        )
        ## COST PER SECOND ##
        prompt_cost = model_info["input_cost_per_second"] * duration
        completion_cost = 0.0

    return prompt_cost, completion_cost