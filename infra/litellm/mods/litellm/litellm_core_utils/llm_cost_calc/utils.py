# What is this?
## Helper utilities for cost_per_token()

import sys
from typing import Optional, Tuple

import litellm
from litellm import verbose_logger
from litellm.types.utils import ModelInfo, Usage
from litellm.utils import get_model_info


def _is_above_128k(tokens: float) -> bool:
    if tokens > 128000:
        return True
    return False


def _generic_cost_per_character(
    model: str,
    custom_llm_provider: str,
    prompt_characters: float,
    completion_characters: float,
    custom_prompt_cost: Optional[float],
    custom_completion_cost: Optional[float],
) -> Tuple[Optional[float], Optional[float]]:
    """
    Calculates cost per character for aspeech/speech calls.

    Calculates the cost per character for a given model, input messages, and response object.

    Input:
        - model: str, the model name without provider prefix
        - custom_llm_provider: str, "vertex_ai-*"
        - prompt_characters: float, the number of input characters
        - completion_characters: float, the number of output characters

    Returns:
        Tuple[Optional[float], Optional[float]] - prompt_cost_in_usd, completion_cost_in_usd.
        - returns None if not able to calculate cost.

    Raises:
        Exception if 'input_cost_per_character' or 'output_cost_per_character' is missing from model_info
    """
    ## GET MODEL INFO
    model_info = litellm.get_model_info(
        model=model, custom_llm_provider=custom_llm_provider
    )

    ## CALCULATE INPUT COST
    try:
        if custom_prompt_cost is None:
            assert (
                "input_cost_per_character" in model_info
                and model_info["input_cost_per_character"] is not None
            ), "model info for model={} does not have 'input_cost_per_character'-pricing\nmodel_info={}".format(
                model, model_info
            )
            custom_prompt_cost = model_info["input_cost_per_character"]

        prompt_cost = prompt_characters * custom_prompt_cost
    except Exception as e:
        verbose_logger.exception(
            "litellm.litellm_core_utils.llm_cost_calc.utils.py::cost_per_character(): Exception occured - {}\nDefaulting to None".format(
                str(e)
            )
        )

        prompt_cost = None

    ## CALCULATE OUTPUT COST
    try:
        if custom_completion_cost is None:
            assert (
                "output_cost_per_character" in model_info
                and model_info["output_cost_per_character"] is not None
            ), "model info for model={} does not have 'output_cost_per_character'-pricing\nmodel_info={}".format(
                model, model_info
            )
            custom_completion_cost = model_info["output_cost_per_character"]
        completion_cost = completion_characters * custom_completion_cost
    except Exception as e:
        verbose_logger.exception(
            "litellm.litellm_core_utils.llm_cost_calc.utils.py::cost_per_character(): Exception occured - {}\nDefaulting to None".format(
                str(e)
            )
        )

        completion_cost = None

    return prompt_cost, completion_cost


def _get_prompt_token_base_cost(model_info: ModelInfo, usage: Usage) -> float:
    """
    Return prompt cost for a given model and usage.

    If input_tokens > 128k and `input_cost_per_token_above_128k_tokens` is set, then we use the `input_cost_per_token_above_128k_tokens` field.
    """
    input_cost_per_token_above_128k_tokens = model_info.get(
        "input_cost_per_token_above_128k_tokens"
    )
    if _is_above_128k(usage.prompt_tokens) and input_cost_per_token_above_128k_tokens:
        return input_cost_per_token_above_128k_tokens
    return model_info["input_cost_per_token"]


def _get_completion_token_base_cost(model_info: ModelInfo, usage: Usage) -> float:
    """
    Return prompt cost for a given model and usage.

    If input_tokens > 128k and `input_cost_per_token_above_128k_tokens` is set, then we use the `input_cost_per_token_above_128k_tokens` field.
    """
    output_cost_per_token_above_128k_tokens = model_info.get(
        "output_cost_per_token_above_128k_tokens"
    )
    if (
        _is_above_128k(usage.completion_tokens)
        and output_cost_per_token_above_128k_tokens
    ):
        return output_cost_per_token_above_128k_tokens
    return model_info["output_cost_per_token"]

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
        per_t_in = 10
        per_t_out = 40
        per_t_in_cache_read = 2.50
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


def generic_cost_per_token(
    model: str, usage: Usage, custom_llm_provider: str
) -> Tuple[float, float]:
    """
    Calculates the cost per token for a given model, prompt tokens, and completion tokens.

    Handles context caching as well.

    Input:
        - model: str, the model name without provider prefix
        - usage: LiteLLM Usage block, containing anthropic caching information

    Returns:
        Tuple[float, float] - prompt_cost_in_usd, completion_cost_in_usd
    """
    ## GET MODEL INFO
    model_info = get_model_info(model=model, custom_llm_provider=custom_llm_provider)

    ## CALCULATE INPUT COST
    ### Cost of processing (non-cache hit + cache hit) + Cost of cache-writing (cache writing)
    prompt_cost = 0.0
    ### PROCESSING COST
    non_cache_hit_tokens = usage.prompt_tokens
    cache_hit_tokens = 0
    cache_write_tokens = 0
    if usage.prompt_tokens_details and usage.prompt_tokens_details.cached_tokens:
        cache_hit_tokens = usage.prompt_tokens_details.cached_tokens
    if usage._cache_creation_input_tokens:
        cache_write_tokens = usage._cache_creation_input_tokens
    non_cache_hit_tokens = non_cache_hit_tokens - cache_hit_tokens - cache_write_tokens


    prompt_base_cost = _get_prompt_token_base_cost(model_info=model_info, usage=usage)

    prompt_cost = float(non_cache_hit_tokens) * prompt_base_cost


    _cache_read_input_token_cost = model_info.get("cache_read_input_token_cost")
    if (
        _cache_read_input_token_cost is not None
        and usage.prompt_tokens_details
        and usage.prompt_tokens_details.cached_tokens
    ):
        prompt_cost += (
            float(usage.prompt_tokens_details.cached_tokens)
            * _cache_read_input_token_cost
        )

    ### CACHE WRITING COST
    _cache_creation_input_token_cost = model_info.get("cache_creation_input_token_cost")
    if _cache_creation_input_token_cost is not None:
        prompt_cost += (
            float(usage._cache_creation_input_tokens) * _cache_creation_input_token_cost
        )

    ## CALCULATE OUTPUT COST
    completion_base_cost = _get_completion_token_base_cost(
        model_info=model_info, usage=usage
    )
    completion_cost = usage["completion_tokens"] * completion_base_cost

    try:
        expected_cost = calculate_costs_agentlib(
            model=model,
            prompt_tokens=usage.prompt_tokens,
            completion_tokens=usage["completion_tokens"],
            cache_creation_input_tokens=usage._cache_creation_input_tokens,
            cache_read_input_tokens=usage.prompt_tokens_details.cached_tokens if usage.prompt_tokens_details else 0
        )

        import datetime
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        print(f"""
[{timestamp}] =============== GENERIC COST PER TOKEN for {model} ===============")
usage: {usage}
non_cache_input_tokens: {non_cache_hit_tokens}
cache_creation_input_tokens: {usage._cache_creation_input_tokens}
cache_read_input_tokens: {usage.prompt_tokens_details.cached_tokens if usage.prompt_tokens_details else 0}
completion_tokens: {usage["completion_tokens"]}
---
p_t_costs: [in:{prompt_base_cost}, cr:{model_info.get("cache_read_input_token_cost")}, cw:{model_info.get("cache_creation_input_token_cost")}, out:{completion_base_cost}]
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