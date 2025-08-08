import yaml
import json
import logging
import os
import requests
from typing import Optional, Literal
from functools import cache

import logging
from logging import NullHandler

try:
    from shellphish_crs_utils.pydatatask.client import PDClient
    from shellphish_crs_utils.models.extended_aixcc_api import ExtendedTaskDetail
    from shellphish_crs_utils import LOG_FORMAT
except ImportError:
    PDClient = None
    ExtendedTaskDetail = None
    LOG_FORMAT = "%(asctime)s | %(levelname)s | %(name)s | %(message)s"

logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)

from opentelemetry._logs import set_logger_provider
from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler, LogData
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor, ConsoleLogExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.exporter.otlp.proto.grpc._log_exporter import (
    OTLPLogExporter,
)

import openlit
import opentelemetry.trace as trace
from opentelemetry.trace import (
    set_tracer_provider,
    Tracer,
    get_tracer,
    Context,
    Span,
    Status,
    StatusCode,
)

from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
from opentelemetry.sdk.trace.id_generator import RandomIdGenerator
from opentelemetry.metrics import set_meter_provider, get_meter
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
from opentelemetry.sdk.metrics.export import ConsoleMetricExporter

CategoryType = Literal[
    "static_analysis",
    "dynamic_analysis",
    "fuzzing",
    "program_analysis",
    "building",
    "input_generation",
    "patch_generation",
    "testing",
    "scoring_submission",
]

openlit_blacklisted_providers = [
    "cohere",
    "mistral",
    "bedrock",
    "vertexai",
    "groq",
    "ollama",
    "gpt4all",
    "elevenlabs",
    "vllm",
    "azure-ai-inference",
    "llama_index",
    "haystack",
    "embedchain",
    "chroma",
    "pinecone",
    "qdrant",
    "milvus",
    "transformers",
]

log = logging.getLogger("crs_telemetry")
log.setLevel(logging.INFO)

class AIxCCBatchSpanProcessor(BatchSpanProcessor):
    def __init__(
        self,
        *args,
        crs_action_category: CategoryType = None,
        crs_action_name: str = None,
        crs_task_metadata: dict = None,
        **kwargs,
    ):
        self.crs_action_category = crs_action_category
        self.crs_action_name = crs_action_name
        self.crs_task_metadata = crs_task_metadata
        super().__init__(*args, **kwargs)

    def on_start(self, span: Span, parent_context: Context):
        span.set_attribute("crs.action.category", self.crs_action_category or "")
        span.set_attribute("crs.action.name", self.crs_action_name or "")
        if os.environ.get("JOB_ID"):
            span.set_attribute("pdt.id", os.environ.get("JOB_ID"))
        if os.environ.get("REPLICA_ID"):
            span.set_attribute("pdt.replica_id", os.environ.get("REPLICA_ID"))
        if os.environ.get("TASK_NAME"):
            span.set_attribute("pdt.task_name", os.environ.get("TASK_NAME"))
        if self.crs_task_metadata:
            for key, value in self.crs_task_metadata.items():
                if not key or not value:
                    continue
                span.set_attribute(key, value)

        bad_keys = [
            k for k, v in span.attributes.items() if isinstance(v, dict)
        ]
        for k in bad_keys:
            span.set_attribute(k, json.dumps(span.attributes[k]))

        super().on_start(span, parent_context)


    def on_end(self, span):
        """
        Safe span processor to avoid sending non-string attributes to the collector.
        """
        attrs = span.attributes.copy()
        for k, v in attrs.items():
            if not isinstance(v, (str, int, float, bool, bytes)) and not (
                isinstance(v, (list, tuple)) and all(isinstance(i, (str, int, float, bool, bytes)) for i in v)
            ):
                span.set_attribute(k, str(v))  # or remove with span.attributes.pop(k)
        super().on_end(span)
 
class AIxCCBatchLogRecordProcessor(BatchLogRecordProcessor):
    def __init__(
        self,
        *args,
        crs_action_category: CategoryType = None,
        crs_action_name: str = None,
        crs_task_metadata: dict = None,
        **kwargs,
    ):
        self.crs_action_category = crs_action_category
        self.crs_action_name = crs_action_name
        self.crs_task_metadata = crs_task_metadata
        super().__init__(*args, **kwargs)

    def emit(self, log_data: LogData):
        log_data.log_record.attributes["crs.action.category"] = self.crs_action_category or ""
        log_data.log_record.attributes["crs.action.name"] = self.crs_action_name or ""
        if os.environ.get("JOB_ID"):
            log_data.log_record.attributes["pdt.id"] = str(os.environ.get("JOB_ID"))
        if os.environ.get("REPLICA_ID"):
            log_data.log_record.attributes["pdt.replica_id"] = str(os.environ.get("REPLICA_ID"))
        if os.environ.get("TASK_NAME"):
            log_data.log_record.attributes["pdt.task_name"] = str(os.environ.get("TASK_NAME"))
        if self.crs_task_metadata:
            for key, value in self.crs_task_metadata.items():
                if not key or not value:
                    continue
                log_data.log_record.attributes[key] = str(value)

        super().emit(log_data)



class PDTIDGenerator(RandomIdGenerator):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.used_pdt_id = False

    def generate_span_id(self) -> int:
        return super().generate_span_id()

    def generate_trace_id(self) -> int:
        if not self.used_pdt_id:
            self.used_pdt_id = True
            return os.environ.get("JOB_ID")
        return super().generate_trace_id()


def should_use_otel() -> bool:
    return os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT") is not None


def is_debug() -> bool:
    return os.environ.get("OTEL_DEBUG") is not None

def get_span_processor(
    crs_action_category: CategoryType, crs_action_name: str, crs_task_metadata: dict
) -> Optional[AIxCCBatchSpanProcessor]:
    if should_use_otel():
        exporter = OTLPSpanExporter(insecure=True)
    elif is_debug():
        exporter = ConsoleSpanExporter()
    else:
        return None
    return AIxCCBatchSpanProcessor(
        exporter,
        crs_action_category=crs_action_category,
        crs_action_name=crs_action_name,
        crs_task_metadata=crs_task_metadata,
    )


@cache
def create_tracer_provider(
    name: str = None,
    crs_action_category: CategoryType = None,
    crs_action_name: str = None,
) -> TracerProvider:
    name = os.environ.get("OTEL_COMPONENT_NAME") or name
    crs_task_metadata = get_metadata()
    span_processor = get_span_processor(
        crs_action_category, crs_action_name, crs_task_metadata
    )
    if span_processor is None:
        return
    tracer_provider = TracerProvider(
        resource=Resource.create(attributes={"service.name": name})
    )
    tracer_provider.add_span_processor(span_processor)
    return tracer_provider


def get_current_span() -> trace.Span:
    return trace.get_current_span()

def get_log_record_processor(crs_action_category: CategoryType = None, crs_action_name: str = None, crs_task_metadata: dict = None) -> AIxCCBatchLogRecordProcessor:
    if should_use_otel():
        exporter = OTLPLogExporter(insecure=True)
    elif is_debug():
        exporter = ConsoleLogExporter()
    else:
        return None
    return AIxCCBatchLogRecordProcessor(
        exporter,
        crs_action_category=crs_action_category,
        crs_action_name=crs_action_name,
        crs_task_metadata=crs_task_metadata,
    )


@cache
def create_logger_provider(name: str = None, crs_action_category: CategoryType = None, crs_action_name: str = None) -> LoggerProvider:
    name = os.environ.get("OTEL_COMPONENT_NAME") or name

    crs_action_category=crs_action_category,
    crs_action_name=crs_action_name,

    crs_task_metadata = get_metadata()
    log_record_processor = get_log_record_processor(crs_action_category, crs_action_name, crs_task_metadata)
    if log_record_processor is None:
        return None

    logger_provider = LoggerProvider(
        resource=Resource.create(attributes={"service.name": name})
    )

    logger_provider.add_log_record_processor(log_record_processor)
    return logger_provider



@cache
def create_meter_provider(name: str = None) -> MeterProvider:
    name = os.environ.get("OTEL_COMPONENT_NAME") or name
    if should_use_otel():
        metric_exporter = OTLPMetricExporter(insecure=True)
    elif is_debug():
        metric_exporter = ConsoleMetricExporter()
    else:
        return None

    reader = PeriodicExportingMetricReader(metric_exporter)
    meter_provider = MeterProvider(
        metric_readers=[reader],
        resource=Resource.create(attributes={"service.name": name}),
    )
    return meter_provider

def is_healthy():
    if os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT"):
        health_check_url = (
            os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT").replace("4317", "13133")
        )
        try:
            response = requests.get(health_check_url, timeout=5)
            return response.status_code == 200
        except Exception as e:
            log.error(f"Error checking health: {e}", exc_info=True)
            return False
    return True

def get_pd_client():
    if PDClient is None:
        raise ValueError("PDClient is not installed")

    CRS_TASK_NUM = os.environ.get("CRS_TASK_NUM", os.environ.get("ARTIPHISHELL_GLOBAL_ENV_CRS_TASK_NUM", None))

    agent_url = os.environ.get(f"PYDATATASK_AGENT_{CRS_TASK_NUM}_PORT",
        os.environ.get("PYDATATASK_AGENT_PORT",
        os.environ.get("PDT_AGENT_URL", "")
    ))
    agent_url = agent_url.replace("tcp://", "http://")
    agent_secret = os.environ.get("AGENT_SECRET", os.environ.get("PDT_AGENT_SECRET", ""))

    if not agent_url:
        log.warning("PD agent URL is not set in environment variables %s", agent_url)
        raise ValueError(f"PD agent URL is not set in environment variables for CRS_TASK_NUM={CRS_TASK_NUM}")

    return PDClient(agent_url, agent_secret)

@cache
def get_metadata() -> dict:
    try:
        client = get_pd_client()
        project_id = os.environ.get("PROJECT_ID")
        if not project_id:
            return {}
        crs_task = client.get_data("pipeline_input", "crs_task", project_id)
        crs_task = ExtendedTaskDetail.model_validate(yaml.safe_load(crs_task))
        return crs_task.metadata
    except ValueError as ve:
        log.warning("PD client not found, removing some telemetry info: %s", ve)
    except Exception as e:
        log.error("Unknown exception trying to find pd: %s", e, exc_info=True)
    return {}


def init_otel(name: str, crs_action_category: CategoryType, crs_action_name: str):
    """
    Initialize the OpenTelemetry tracer, logs, and meter for the given name.
    """
    if os.environ.get("OTEL_COMPONENT_NAME") is not None:
        return

    if not is_healthy():
        log.warning("OpenTelemetry is not healthy, attempting initialization anyway")

    os.environ["OTEL_COMPONENT_NAME"] = name
    tracer_provider = create_tracer_provider(name, crs_action_category, crs_action_name)
    if tracer_provider:
        set_tracer_provider(tracer_provider)

    logger_provider = create_logger_provider(name, crs_action_category, crs_action_name)
    if logger_provider:
        set_logger_provider(logger_provider)
        logger = logging.getLogger()
        logger.addHandler(get_otel_logging_handler(name, crs_action_category, crs_action_name))
        if not any(x for x in logger.handlers if isinstance(x, logging.StreamHandler)):
            # Just to avoid duplicate logging
            logger.addHandler(logging.StreamHandler())

    meter_provider = create_meter_provider(name)

    if meter_provider:
        set_meter_provider(meter_provider)


def init_llm_otel(name: str = None):
    """
    Initialize the OpenTelemetry tracer and meter for the LLM.
    """
    name = os.environ.get("OTEL_COMPONENT_NAME") or name
    if not is_healthy():
        log.warning("OpenTelemetry is not healthy, attempting initialization anyway")

    print("INIT LLM OTEL")
    print("NAME:", name)
    openlit.init(
        application_name=name,
        tracer=get_otel_tracer(name),
        meter=get_otel_meter(name),
        disabled_instrumentors=openlit_blacklisted_providers,
    )
    print(openlit.instrumentation.langchain.langchain.chat)


def get_otel_tracer(name: str = None) -> Tracer:
    """
    Get a tracer from the OpenTelemetry tracer provider.
    """
    name = os.environ.get("OTEL_COMPONENT_NAME") or name
    return get_tracer(name)


def get_otel_meter(name: str = None):
    """
    Get a meter from the OpenTelemetry meter provider.
    """
    name = os.environ.get("OTEL_COMPONENT_NAME") or name
    return get_meter(name)


@cache
def get_otel_logging_handler(name: str = None, crs_action_category: CategoryType = None, crs_action_name: str = None):
    """
    Create a logging handler that logs to the console and sends logs to the OpenTelemetry collector.
    """
    name = os.environ.get("OTEL_COMPONENT_NAME") or name
    logger_provider = create_logger_provider(name, crs_action_category, crs_action_name)
    if logger_provider:
        handler = LoggingHandler(level=logging.DEBUG, logger_provider=logger_provider)
        return handler
    else:
        return NullHandler()


def status_ok() -> Status:
    return Status(StatusCode.OK)


def status_error() -> Status:
    return Status(StatusCode.ERROR)
