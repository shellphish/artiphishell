# pylint: disable=duplicate-code, broad-exception-caught, too-many-statements, unused-argument, unused-import
"""
Module for monitoring Langchain applications.
"""

import logging
import jinja2
from opentelemetry.trace import SpanKind, Status, StatusCode
from opentelemetry.sdk.resources import TELEMETRY_SDK_NAME
from openlit.__helpers import handle_exception, get_chat_model_cost
from openlit.semcov import SemanticConvetion
from agentlib.lib.agents.agent import TokenUsage


# Initialize logger for logging potential issues and operations
logger = logging.getLogger(__name__)


def general_wrap(
    gen_ai_endpoint,
    version,
    environment,
    application_name,
    tracer,
    pricing_info,
    trace_content,
    metrics,
    disable_metrics,
):
    """
    Creates a wrapper around a function call to trace and log its execution metrics.

    This function wraps any given function to measure its execution time,
    log its operation, and trace its execution using OpenTelemetry.

    Parameters:
    - gen_ai_endpoint (str): A descriptor or name for the endpoint being traced.
    - version (str): The version of the Langchain application.
    - environment (str): The deployment environment (e.g., 'production', 'development').
    - application_name (str): Name of the Langchain application.
    - tracer (opentelemetry.trace.Tracer): The tracer object used for OpenTelemetry tracing.
    - pricing_info (dict): Information about the pricing for internal metrics (currently not used).
    - trace_content (bool): Flag indicating whether to trace the content of the response.

    Returns:
    - function: A higher-order function that takes a function 'wrapped' and returns
                a new function that wraps 'wrapped' with additional tracing and logging.
    """

    def wrapper(wrapped, instance, args, kwargs):
        """
        An inner wrapper function that executes the wrapped function, measures execution
        time, and records trace data using OpenTelemetry.

        Parameters:
        - wrapped (Callable): The original function that this wrapper will execute.
        - instance (object): The instance to which the wrapped function belongs. This
                             is used for instance methods. For static and classmethods,
                             this may be None.
        - args (tuple): Positional arguments passed to the wrapped function.
        - kwargs (dict): Keyword arguments passed to the wrapped function.

        Returns:
        - The result of the wrapped function call.

        The wrapper initiates a span with the provided tracer, sets various attributes
        on the span based on the function's execution and response, and ensures
        errors are handled and logged appropriately.
        """
        with tracer.start_as_current_span(
            gen_ai_endpoint, kind=SpanKind.CLIENT
        ) as span:
            response = wrapped(*args, **kwargs)

            try:
                span.set_attribute(TELEMETRY_SDK_NAME, "openlit")
                span.set_attribute(
                    SemanticConvetion.GEN_AI_SYSTEM,
                    SemanticConvetion.GEN_AI_SYSTEM_LANGCHAIN,
                )
                span.set_attribute(SemanticConvetion.GEN_AI_ENDPOINT, gen_ai_endpoint)
                span.set_attribute(SemanticConvetion.GEN_AI_ENVIRONMENT, environment)
                span.set_attribute(
                    SemanticConvetion.GEN_AI_TYPE,
                    SemanticConvetion.GEN_AI_TYPE_FRAMEWORK,
                )
                span.set_attribute(
                    SemanticConvetion.GEN_AI_APPLICATION_NAME, application_name
                )
                span.set_attribute(
                    SemanticConvetion.GEN_AI_RETRIEVAL_SOURCE,
                    response[0].metadata["source"],
                )
                span.set_status(Status(StatusCode.OK))

                # Return original response
                return response

            except Exception as e:
                handle_exception(span, e)
                logger.error("Error in trace creation: %s", e, exc_info=True)

                # Return original response
                return response

    return wrapper


def hub(
    gen_ai_endpoint,
    version,
    environment,
    application_name,
    tracer,
    pricing_info,
    trace_content,
    metrics,
    disable_metrics,
):
    """
    Creates a wrapper around Langchain hub operations for tracing and logging.

    Similar to `general_wrap`, this function focuses on wrapping functions involved
    in interacting with the Langchain hub, adding specific metadata relevant to
    hub operations to the span attributes.

    Parameters:
    - gen_ai_endpoint (str): A descriptor or name for the Langchain hub endpoint.
    - version (str): The version of the Langchain application.
    - environment (str): The deployment environment, such as 'production' or 'development'.
    - application_name (str): Name of the Langchain application.
    - tracer (opentelemetry.trace.Tracer): The tracer for OpenTelemetry tracing.
    - pricing_info (dict): Pricing information for the operation (not currently used).
    - trace_content (bool): Indicates if the content of the response should be traced.

    Returns:
    - function: A new function that wraps the original hub operation call with added
                logging, tracing, and metric calculation functionalities.
    """

    def wrapper(wrapped, instance, args, kwargs):
        """
        An inner wrapper specifically designed for Langchain hub operations,
        providing tracing, logging, and execution metrics.

        Parameters:
        - wrapped (Callable): The original hub operation function to be executed.
        - instance (object): The instance of the class where the hub operation
                             method is defined. May be None for static or class methods.
        - args (tuple): Positional arguments to pass to the hub operation function.
        - kwargs (dict): Keyword arguments to pass to the hub operation function.

        Returns:
        - The result of executing the hub operation function.

        This wrapper captures additional metadata relevant to Langchain hub operations,
        creating spans with specific attributes and metrics that reflect the nature of
        each hub call.
        """

        with tracer.start_as_current_span(
            gen_ai_endpoint, kind=SpanKind.CLIENT
        ) as span:
            response = wrapped(*args, **kwargs)

            try:
                span.set_attribute(TELEMETRY_SDK_NAME, "openlit")
                span.set_attribute(
                    SemanticConvetion.GEN_AI_SYSTEM,
                    SemanticConvetion.GEN_AI_SYSTEM_LANGCHAIN,
                )
                span.set_attribute(SemanticConvetion.GEN_AI_ENDPOINT, gen_ai_endpoint)
                span.set_attribute(SemanticConvetion.GEN_AI_ENVIRONMENT, environment)
                span.set_attribute(
                    SemanticConvetion.GEN_AI_TYPE,
                    SemanticConvetion.GEN_AI_TYPE_FRAMEWORK,
                )
                span.set_attribute(
                    SemanticConvetion.GEN_AI_APPLICATION_NAME, application_name
                )
                span.set_attribute(
                    SemanticConvetion.GEN_AI_HUB_OWNER,
                    response.metadata["lc_hub_owner"],
                )
                span.set_attribute(
                    SemanticConvetion.GEN_AI_HUB_REPO, response.metadata["lc_hub_repo"]
                )
                span.set_status(Status(StatusCode.OK))

                return response

            except Exception as e:
                handle_exception(span, e)
                logger.error("Error in trace creation: %s", e, exc_info=True)

                # Return original response
                return response

    return wrapper


def allm(
    gen_ai_endpoint,
    version,
    environment,
    application_name,
    tracer,
    pricing_info,
    trace_content,
    metrics,
    disable_metrics,
):
    """
    Creates a wrapper around a function call to trace and log its execution metrics.

    This function wraps any given function to measure its execution time,
    log its operation, and trace its execution using OpenTelemetry.

    Parameters:
    - gen_ai_endpoint (str): A descriptor or name for the endpoint being traced.
    - version (str): The version of the Langchain application.
    - environment (str): The deployment environment (e.g., 'production', 'development').
    - application_name (str): Name of the Langchain application.
    - tracer (opentelemetry.trace.Tracer): The tracer object used for OpenTelemetry tracing.
    - pricing_info (dict): Information about the pricing for internal metrics (currently not used).
    - trace_content (bool): Flag indicating whether to trace the content of the response.

    Returns:
    - function: A higher-order function that takes a function 'wrapped' and returns
                a new function that wraps 'wrapped' with additional tracing and logging.
    """

    async def wrapper(wrapped, instance, args, kwargs):
        """
        An inner wrapper function that executes the wrapped function, measures execution
        time, and records trace data using OpenTelemetry.

        Parameters:
        - wrapped (Callable): The original function that this wrapper will execute.
        - instance (object): The instance to which the wrapped function belongs. This
                             is used for instance methods. For static and classmethods,
                             this may be None.
        - args (tuple): Positional arguments passed to the wrapped function.
        - kwargs (dict): Keyword arguments passed to the wrapped function.

        Returns:
        - The result of the wrapped function call.

        The wrapper initiates a span with the provided tracer, sets various attributes
        on the span based on the function's execution and response, and ensures
        errors are handled and logged appropriately.
        """
        with tracer.start_as_current_span(
            gen_ai_endpoint, kind=SpanKind.CLIENT
        ) as span:
            response = await wrapped(*args, **kwargs)

            try:
                prompt = args[0] or ""
                # input_tokens = general_tokens(prompt)
                # output_tokens = general_tokens(response)

                # # Calculate cost of the operation
                # cost = get_chat_model_cost(
                #     str(getattr(instance, 'model')),
                #     pricing_info, input_tokens, output_tokens
                # )

                span.set_attribute(TELEMETRY_SDK_NAME, "openlit")
                span.set_attribute(
                    SemanticConvetion.GEN_AI_SYSTEM,
                    SemanticConvetion.GEN_AI_SYSTEM_LANGCHAIN,
                )
                span.set_attribute(SemanticConvetion.GEN_AI_ENDPOINT, gen_ai_endpoint)
                span.set_attribute(SemanticConvetion.GEN_AI_ENVIRONMENT, environment)
                span.set_attribute(
                    SemanticConvetion.GEN_AI_TYPE,
                    SemanticConvetion.GEN_AI_TYPE_FRAMEWORK,
                )
                span.set_attribute(
                    SemanticConvetion.GEN_AI_APPLICATION_NAME, application_name
                )
                span.set_attribute(
                    SemanticConvetion.GEN_AI_REQUEST_MODEL,
                    str(getattr(instance, "model")),
                )
                span.set_attribute(
                    SemanticConvetion.GEN_AI_REQUEST_TEMPERATURE,
                    str(getattr(instance, "temperature")),
                )
                span.set_attribute(
                    SemanticConvetion.GEN_AI_REQUEST_TOP_K,
                    str(getattr(instance, "top_k")),
                )
                span.set_attribute(
                    SemanticConvetion.GEN_AI_REQUEST_TOP_P,
                    str(getattr(instance, "top_p")),
                )
                span.set_attribute(SemanticConvetion.GEN_AI_REQUEST_IS_STREAM, False)
                # span.set_attribute(SemanticConvetion.GEN_AI_USAGE_PROMPT_TOKENS,
                #                     input_tokens)
                # span.set_attribute(SemanticConvetion.GEN_AI_USAGE_COMPLETION_TOKENS,
                #                     output_tokens)
                # span.set_attribute(SemanticConvetion.GEN_AI_USAGE_TOTAL_TOKENS,
                #                     input_tokens + output_tokens)
                # span.set_attribute(SemanticConvetion.GEN_AI_USAGE_COST,
                #                     cost)
                if trace_content:
                    span.add_event(
                        name=SemanticConvetion.GEN_AI_CONTENT_PROMPT_EVENT,
                        attributes={
                            SemanticConvetion.GEN_AI_CONTENT_PROMPT: prompt,
                        },
                    )
                    span.add_event(
                        name=SemanticConvetion.GEN_AI_CONTENT_COMPLETION_EVENT,
                        attributes={
                            SemanticConvetion.GEN_AI_CONTENT_COMPLETION: response,
                        },
                    )

                span.set_status(Status(StatusCode.OK))

                # if disable_metrics is False:
                #     attributes = {
                #         TELEMETRY_SDK_NAME:
                #             "openlit",
                #         SemanticConvetion.GEN_AI_APPLICATION_NAME:
                #             application_name,
                #         SemanticConvetion.GEN_AI_SYSTEM:
                #             SemanticConvetion.GEN_AI_SYSTEM_LANGCHAIN,
                #         SemanticConvetion.GEN_AI_ENVIRONMENT:
                #             environment,
                #         SemanticConvetion.GEN_AI_TYPE:
                #             SemanticConvetion.GEN_AI_TYPE_CHAT,
                #         SemanticConvetion.GEN_AI_REQUEST_MODEL:
                #             str(getattr(instance, 'model'))
                #     }

                #     metrics["genai_requests"].add(1, attributes)
                #     metrics["genai_total_tokens"].add(
                #         input_tokens + output_tokens, attributes
                #     )
                #     metrics["genai_completion_tokens"].add(output_tokens, attributes)
                #     metrics["genai_prompt_tokens"].add(input_tokens, attributes)
                #     metrics["genai_cost"].record(cost, attributes)

                # Return original response
                return response

            except Exception as e:
                handle_exception(span, e)
                logger.error("Error in trace creation: %s", e, exc_info=True)

                # Return original response
                return response

    return wrapper


def llm(
    gen_ai_endpoint,
    version,
    environment,
    application_name,
    tracer,
    pricing_info,
    trace_content,
    metrics,
    disable_metrics,
):
    """
    Creates a wrapper around a function call to trace and log its execution metrics.

    This function wraps any given function to measure its execution time,
    log its operation, and trace its execution using OpenTelemetry.

    Parameters:
    - gen_ai_endpoint (str): A descriptor or name for the endpoint being traced.
    - version (str): The version of the Langchain application.
    - environment (str): The deployment environment (e.g., 'production', 'development').
    - application_name (str): Name of the Langchain application.
    - tracer (opentelemetry.trace.Tracer): The tracer object used for OpenTelemetry tracing.
    - pricing_info (dict): Information about the pricing for internal metrics (currently not used).
    - trace_content (bool): Flag indicating whether to trace the content of the response.

    Returns:
    - function: A higher-order function that takes a function 'wrapped' and returns
                a new function that wraps 'wrapped' with additional tracing and logging.
    """

    def wrapper(wrapped, instance, args, kwargs):
        """
        An inner wrapper function that executes the wrapped function, measures execution
        time, and records trace data using OpenTelemetry.

        Parameters:
        - wrapped (Callable): The original function that this wrapper will execute.
        - instance (object): The instance to which the wrapped function belongs. This
                             is used for instance methods. For static and classmethods,
                             this may be None.
        - args (tuple): Positional arguments passed to the wrapped function.
        - kwargs (dict): Keyword arguments passed to the wrapped function.

        Returns:
        - The result of the wrapped function call.

        The wrapper initiates a span with the provided tracer, sets various attributes
        on the span based on the function's execution and response, and ensures
        errors are handled and logged appropriately.
        """
        with tracer.start_as_current_span(
            gen_ai_endpoint, kind=SpanKind.CLIENT
        ) as span:
            response = wrapped(*args, **kwargs)

            try:
                prompt = args[0] or ""
                # input_tokens = general_tokens(prompt)
                # output_tokens = general_tokens(response)

                # # Calculate cost of the operation
                # cost = get_chat_model_cost(
                #     str(getattr(instance, 'model')),
                #     pricing_info, input_tokens, output_tokens
                # )

                span.set_attribute(TELEMETRY_SDK_NAME, "openlit")
                span.set_attribute(
                    SemanticConvetion.GEN_AI_SYSTEM,
                    SemanticConvetion.GEN_AI_SYSTEM_LANGCHAIN,
                )
                span.set_attribute(SemanticConvetion.GEN_AI_ENDPOINT, gen_ai_endpoint)
                span.set_attribute(SemanticConvetion.GEN_AI_ENVIRONMENT, environment)
                span.set_attribute(
                    SemanticConvetion.GEN_AI_TYPE,
                    SemanticConvetion.GEN_AI_TYPE_FRAMEWORK,
                )
                span.set_attribute(
                    SemanticConvetion.GEN_AI_APPLICATION_NAME, application_name
                )
                span.set_attribute(
                    SemanticConvetion.GEN_AI_REQUEST_MODEL,
                    str(getattr(instance, "model")),
                )
                span.set_attribute(
                    SemanticConvetion.GEN_AI_REQUEST_TEMPERATURE,
                    str(getattr(instance, "temperature")),
                )
                span.set_attribute(
                    SemanticConvetion.GEN_AI_REQUEST_TOP_K,
                    str(getattr(instance, "top_k")),
                )
                span.set_attribute(
                    SemanticConvetion.GEN_AI_REQUEST_TOP_P,
                    str(getattr(instance, "top_p")),
                )
                span.set_attribute(SemanticConvetion.GEN_AI_REQUEST_IS_STREAM, False)
                # span.set_attribute(SemanticConvetion.GEN_AI_USAGE_PROMPT_TOKENS,
                #                     input_tokens)
                # span.set_attribute(SemanticConvetion.GEN_AI_USAGE_COMPLETION_TOKENS,
                #                     output_tokens)
                # span.set_attribute(SemanticConvetion.GEN_AI_USAGE_TOTAL_TOKENS,
                #                     input_tokens + output_tokens)
                # span.set_attribute(SemanticConvetion.GEN_AI_USAGE_COST,
                #                     cost)
                if trace_content:
                    span.add_event(
                        name=SemanticConvetion.GEN_AI_CONTENT_PROMPT_EVENT,
                        attributes={
                            SemanticConvetion.GEN_AI_CONTENT_PROMPT: prompt,
                        },
                    )
                    span.add_event(
                        name=SemanticConvetion.GEN_AI_CONTENT_COMPLETION_EVENT,
                        attributes={
                            SemanticConvetion.GEN_AI_CONTENT_COMPLETION: response,
                        },
                    )

                span.set_status(Status(StatusCode.OK))

                # if disable_metrics is False:
                #     attributes = {
                #         TELEMETRY_SDK_NAME:
                #             "openlit",
                #         SemanticConvetion.GEN_AI_APPLICATION_NAME:
                #             application_name,
                #         SemanticConvetion.GEN_AI_SYSTEM:
                #             SemanticConvetion.GEN_AI_SYSTEM_LANGCHAIN,
                #         SemanticConvetion.GEN_AI_ENVIRONMENT:
                #             environment,
                #         SemanticConvetion.GEN_AI_TYPE:
                #             SemanticConvetion.GEN_AI_TYPE_CHAT,
                #         SemanticConvetion.GEN_AI_REQUEST_MODEL:
                #             str(getattr(instance, 'model'))
                #     }

                #     metrics["genai_requests"].add(1, attributes)
                #     metrics["genai_total_tokens"].add(
                #         input_tokens + output_tokens, attributes
                #     )
                #     metrics["genai_completion_tokens"].add(output_tokens, attributes)
                #     metrics["genai_prompt_tokens"].add(input_tokens, attributes)
                #     metrics["genai_cost"].record(cost, attributes)

                # Return original response
                return response

            except Exception as e:
                handle_exception(span, e)
                logger.error("Error in trace creation: %s", e, exc_info=True)

                # Return original response
                return response

    return wrapper


def chat(
    gen_ai_endpoint,
    version,
    environment,
    application_name,
    tracer,
    pricing_info,
    trace_content,
    metrics,
    disable_metrics,
):
    """
    Creates a wrapper around a function call to trace and log its execution metrics.

    This function wraps any given function to measure its execution time,
    log its operation, and trace its execution using OpenTelemetry.

    Parameters:
    - gen_ai_endpoint (str): A descriptor or name for the endpoint being traced.
    - version (str): The version of the Langchain application.
    - environment (str): The deployment environment (e.g., 'production', 'development').
    - application_name (str): Name of the Langchain application.
    - tracer (opentelemetry.trace.Tracer): The tracer object used for OpenTelemetry tracing.
    - pricing_info (dict): Information about the pricing for internal metrics (currently not used).
    - trace_content (bool): Flag indicating whether to trace the content of the response.

    Returns:
    - function: A higher-order function that takes a function 'wrapped' and returns
                a new function that wraps 'wrapped' with additional tracing and logging.
    """

    def wrapper(wrapped, instance, args, kwargs):
        """
        An inner wrapper function that executes the wrapped function, measures execution
        time, and records trace data using OpenTelemetry.

        Parameters:
        - wrapped (Callable): The original function that this wrapper will execute.
        - instance (object): The instance to which the wrapped function belongs. This
                             is used for instance methods. For static and classmethods,
                             this may be None.
        - args (tuple): Positional arguments passed to the wrapped function.
        - kwargs (dict): Keyword arguments passed to the wrapped function.

        Returns:
        - The result of the wrapped function call.

        The wrapper initiates a span with the provided tracer, sets various attributes
        on the span based on the function's execution and response, and ensures
        errors are handled and logged appropriately.
        """
        with tracer.start_as_current_span(
            gen_ai_endpoint, kind=SpanKind.CLIENT
        ) as span:
            response = wrapped(*args, **kwargs)

            try:
                input_tokens = response.response_metadata["usage"].get(
                    "prompt_tokens", 0
                )
                output_tokens = response.response_metadata["usage"].get(
                    "completion_tokens", 0
                )

                if "claude" in instance.model_name:
                    cached_creation_tokens = response.response_metadata["usage"].get(
                        "cache_creation_input_tokens", 0
                    )
                    cached_read_tokens = response.response_metadata["usage"].get(
                        "cache_read_input_tokens", 0
                    )
                else:
                    cached_creation_tokens = 0
                    prompt_token_details = response.response_metadata["usage"].get("prompt_tokens_details", {}) or {}
                    cached_read_tokens = prompt_token_details.get("cached_tokens", 0)

                cost = TokenUsage.calculate_costs(
                    instance.model_name,
                    input_tokens,
                    output_tokens,
                    cached_creation_tokens,
                    cached_read_tokens,
                )

                span.set_attribute(TELEMETRY_SDK_NAME, "openlit")
                span.set_attribute(
                    SemanticConvetion.GEN_AI_SYSTEM,
                    SemanticConvetion.GEN_AI_SYSTEM_LANGCHAIN,
                )
                span.set_attribute(SemanticConvetion.GEN_AI_ENDPOINT, gen_ai_endpoint)
                span.set_attribute(SemanticConvetion.GEN_AI_ENVIRONMENT, environment)
                span.set_attribute(
                    SemanticConvetion.GEN_AI_TYPE, SemanticConvetion.GEN_AI_TYPE_CHAT
                )
                span.set_attribute(
                    SemanticConvetion.GEN_AI_APPLICATION_NAME, application_name
                )
                span.set_attribute(
                    SemanticConvetion.GEN_AI_REQUEST_MODEL, instance.model_name
                )
                span.set_attribute(
                    SemanticConvetion.GEN_AI_REQUEST_TEMPERATURE,
                    str(getattr(instance, "temperature")),
                )
                span.set_attribute(
                    SemanticConvetion.GEN_AI_REQUEST_TOP_K,
                    str(getattr(instance, "top_k")),
                )
                span.set_attribute(
                    SemanticConvetion.GEN_AI_REQUEST_TOP_P,
                    str(getattr(instance, "top_p")),
                )
                span.set_attribute(
                    SemanticConvetion.GEN_AI_RESPONSE_FINISH_REASON,
                    [response.response_metadata.get("finish_reason", "unknown")],
                )
                span.set_attribute(SemanticConvetion.GEN_AI_REQUEST_IS_STREAM, False)
                span.set_attribute(
                    SemanticConvetion.GEN_AI_USAGE_PROMPT_TOKENS, input_tokens
                )
                span.set_attribute(
                    SemanticConvetion.GEN_AI_USAGE_COMPLETION_TOKENS, output_tokens
                )
                span.set_attribute(
                    SemanticConvetion.GEN_AI_USAGE_CACHED_CREATION_TOKENS,
                    cached_creation_tokens,
                )
                span.set_attribute(
                    SemanticConvetion.GEN_AI_USAGE_CACHED_READ_TOKENS,
                    cached_read_tokens,
                )

                span.set_attribute(
                    SemanticConvetion.GEN_AI_USAGE_TOTAL_TOKENS,
                    input_tokens + output_tokens,
                )
                span.set_attribute(
                    SemanticConvetion.GEN_AI_USAGE_PROMPT_COST,
                    cost["prompt_cost"]
                )
                span.set_attribute(
                    SemanticConvetion.GEN_AI_USAGE_COMPLETION_COST,
                    cost["completion_cost"],
                )
                span.set_attribute(
                    SemanticConvetion.GEN_AI_USAGE_COST, cost["total_cost"]
                )
                if trace_content:
                    for message in args[0].messages:
                        span.add_event(
                            name=SemanticConvetion.GEN_AI_CONTENT_PROMPT_EVENT,
                            attributes={
                                SemanticConvetion.GEN_AI_CONTENT_PROMPT: jinja2.Template(
                                    getattr(message, "prompt_template", "")
                                ).render(**getattr(message, "prompt_args", {})),
                            },
                        )
                    span.add_event(
                        name=SemanticConvetion.GEN_AI_CONTENT_COMPLETION_EVENT,
                        attributes={
                            SemanticConvetion.GEN_AI_CONTENT_COMPLETION: response.content,
                        },
                    )

                span.set_status(Status(StatusCode.OK))

                if disable_metrics is False:
                    attributes = {
                        TELEMETRY_SDK_NAME: "openlit",
                        SemanticConvetion.GEN_AI_APPLICATION_NAME: application_name,
                        SemanticConvetion.GEN_AI_SYSTEM: SemanticConvetion.GEN_AI_SYSTEM_LANGCHAIN,
                        SemanticConvetion.GEN_AI_ENVIRONMENT: environment,
                        SemanticConvetion.GEN_AI_TYPE: SemanticConvetion.GEN_AI_TYPE_CHAT,
                        SemanticConvetion.GEN_AI_REQUEST_MODEL: instance.model_name,
                    }

                    metrics["genai_requests"].add(1, attributes)
                    metrics["genai_cached_creation_tokens"].add(
                        cached_creation_tokens, attributes
                    )
                    metrics["genai_cached_read_tokens"].add(
                        cached_read_tokens, attributes
                    )
                    metrics["genai_total_tokens"].add(
                        input_tokens + output_tokens, attributes
                    )
                    metrics["genai_completion_tokens"].add(output_tokens, attributes)
                    metrics["genai_prompt_tokens"].add(input_tokens, attributes)
                    metrics["genai_prompt_cost"].record(cost["prompt_cost"], attributes)
                    metrics["genai_completion_cost"].record(
                        cost["completion_cost"], attributes
                    )
                    metrics["genai_cost"].record(cost["total_cost"], attributes)

                # Return original response
                return response

            except Exception as e:
                handle_exception(span, e)
                logger.error("Error in trace creation: %s", e, exc_info=True)

                # Return original response
                return response

    return wrapper


def achat(
    gen_ai_endpoint,
    version,
    environment,
    application_name,
    tracer,
    pricing_info,
    trace_content,
    metrics,
    disable_metrics,
):
    """
    Creates a wrapper around a function call to trace and log its execution metrics.

    This function wraps any given function to measure its execution time,
    log its operation, and trace its execution using OpenTelemetry.

    Parameters:
    - gen_ai_endpoint (str): A descriptor or name for the endpoint being traced.
    - version (str): The version of the Langchain application.
    - environment (str): The deployment environment (e.g., 'production', 'development').
    - application_name (str): Name of the Langchain application.
    - tracer (opentelemetry.trace.Tracer): The tracer object used for OpenTelemetry tracing.
    - pricing_info (dict): Information about the pricing for internal metrics (currently not used).
    - trace_content (bool): Flag indicating whether to trace the content of the response.

    Returns:
    - function: A higher-order function that takes a function 'wrapped' and returns
                a new function that wraps 'wrapped' with additional tracing and logging.
    """

    async def wrapper(wrapped, instance, args, kwargs):
        """
        An inner wrapper function that executes the wrapped function, measures execution
        time, and records trace data using OpenTelemetry.

        Parameters:
        - wrapped (Callable): The original function that this wrapper will execute.
        - instance (object): The instance to which the wrapped function belongs. This
                             is used for instance methods. For static and classmethods,
                             this may be None.
        - args (tuple): Positional arguments passed to the wrapped function.
        - kwargs (dict): Keyword arguments passed to the wrapped function.

        Returns:
        - The result of the wrapped function call.

        The wrapper initiates a span with the provided tracer, sets various attributes
        on the span based on the function's execution and response, and ensures
        errors are handled and logged appropriately.
        """
        with tracer.start_as_current_span(
            gen_ai_endpoint, kind=SpanKind.CLIENT
        ) as span:
            response = await wrapped(*args, **kwargs)

            try:
                input_tokens = response.response_metadata.get("prompt_eval_count", 0)
                output_tokens = response.response_metadata.get("eval_count", 0)

                # Calculate cost of the operation
                cost = get_chat_model_cost(
                    str(getattr(instance, "model")),
                    pricing_info,
                    input_tokens,
                    output_tokens,
                )

                span.set_attribute(TELEMETRY_SDK_NAME, "openlit")
                span.set_attribute(
                    SemanticConvetion.GEN_AI_SYSTEM,
                    SemanticConvetion.GEN_AI_SYSTEM_LANGCHAIN,
                )
                span.set_attribute(SemanticConvetion.GEN_AI_ENDPOINT, gen_ai_endpoint)
                span.set_attribute(SemanticConvetion.GEN_AI_ENVIRONMENT, environment)
                span.set_attribute(
                    SemanticConvetion.GEN_AI_TYPE, SemanticConvetion.GEN_AI_TYPE_CHAT
                )
                span.set_attribute(
                    SemanticConvetion.GEN_AI_APPLICATION_NAME, application_name
                )
                span.set_attribute(
                    SemanticConvetion.GEN_AI_REQUEST_MODEL,
                    str(getattr(instance, "model")),
                )
                span.set_attribute(
                    SemanticConvetion.GEN_AI_REQUEST_TEMPERATURE,
                    str(getattr(instance, "temperature")),
                )
                span.set_attribute(
                    SemanticConvetion.GEN_AI_REQUEST_TOP_K,
                    str(getattr(instance, "top_k")),
                )
                span.set_attribute(
                    SemanticConvetion.GEN_AI_REQUEST_TOP_P,
                    str(getattr(instance, "top_p")),
                )
                span.set_attribute(
                    SemanticConvetion.GEN_AI_RESPONSE_FINISH_REASON,
                    [response.response_metadata.get("done_reason", response.response_metadata.get("finish_reason", "unknown"))],
                )
                span.set_attribute(SemanticConvetion.GEN_AI_REQUEST_IS_STREAM, False)
                span.set_attribute(
                    SemanticConvetion.GEN_AI_USAGE_PROMPT_TOKENS, input_tokens
                )
                span.set_attribute(
                    SemanticConvetion.GEN_AI_USAGE_COMPLETION_TOKENS, output_tokens
                )
                span.set_attribute(
                    SemanticConvetion.GEN_AI_USAGE_TOTAL_TOKENS,
                    input_tokens + output_tokens,
                )
                span.set_attribute(SemanticConvetion.GEN_AI_USAGE_COST, cost)
                if trace_content:
                    span.add_event(
                        name=SemanticConvetion.GEN_AI_CONTENT_PROMPT_EVENT,
                        attributes={
                            SemanticConvetion.GEN_AI_CONTENT_PROMPT: args[0],
                        },
                    )
                    span.add_event(
                        name=SemanticConvetion.GEN_AI_CONTENT_COMPLETION_EVENT,
                        attributes={
                            SemanticConvetion.GEN_AI_CONTENT_COMPLETION: response.content,
                        },
                    )

                span.set_status(Status(StatusCode.OK))

                if disable_metrics is False:
                    attributes = {
                        TELEMETRY_SDK_NAME: "openlit",
                        SemanticConvetion.GEN_AI_APPLICATION_NAME: application_name,
                        SemanticConvetion.GEN_AI_SYSTEM: SemanticConvetion.GEN_AI_SYSTEM_LANGCHAIN,
                        SemanticConvetion.GEN_AI_ENVIRONMENT: environment,
                        SemanticConvetion.GEN_AI_TYPE: SemanticConvetion.GEN_AI_TYPE_CHAT,
                        SemanticConvetion.GEN_AI_REQUEST_MODEL: str(
                            getattr(instance, "model")
                        ),
                    }

                    metrics["genai_requests"].add(1, attributes)
                    metrics["genai_total_tokens"].add(
                        input_tokens + output_tokens, attributes
                    )
                    metrics["genai_completion_tokens"].add(output_tokens, attributes)
                    metrics["genai_prompt_tokens"].add(input_tokens, attributes)
                    metrics["genai_cost"].record(cost, attributes)

                # Return original response
                return response

            except Exception as e:
                handle_exception(span, e)
                logger.error("Error in trace creation: %s", e, exc_info=True)

                # Return original response
                return response

    return wrapper
