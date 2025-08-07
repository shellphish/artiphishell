import logging
import sys
import time

import structlog
from fastapi import Request, Response
from uvicorn._types import HTTPScope
from uvicorn.protocols.utils import get_path_with_query_string

API_LOGGER = structlog.stdlib.get_logger("api.access")


def drop_extras(extras):
    def drop(_, __, event_dict):
        for key in extras:
            event_dict.pop(key, None)
        return event_dict

    return drop


def setup_logging():
    processors = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.stdlib.ExtraAdder(),
        drop_extras(["color_message"]),
        structlog.processors.TimeStamper(fmt="%Y-%m-%d %H:%M:%S", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    if sys.stderr.isatty():
        processors += [structlog.dev.ConsoleRenderer()]
    else:
        processors += [
            structlog.processors.dict_tracebacks,
            structlog.processors.JSONRenderer(),
        ]

    structlog.configure(
        processors=processors,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    for logger in ["uvicorn", "uvicorn.error", "uvicorn.access"]:
        logging.getLogger(logger).handlers.clear()
        logging.getLogger(logger).propagate = False

    logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG)

    logging.getLogger("vyper").setLevel(logging.WARNING)


async def logging_middleware(request: Request, call_next) -> Response:
    start_time = time.perf_counter_ns()

    response = Response(status_code=500)
    try:
        response = await call_next(request)
    except Exception:
        structlog.stdlib.get_logger("api.error").exception("Uncaught exception")
        raise
    finally:
        process_time = time.perf_counter_ns() - start_time
        status_code = response.status_code

        # these types are always compatible, but we'd have to check key presence at
        # runtime to make mypy happy, which would be slow
        scope = HTTPScope(request.scope)  # type: ignore[misc]

        url = get_path_with_query_string(scope)

        client_host = "-" if request.client is None else request.client.host
        client_port = "-" if request.client is None else request.client.port

        http_method = request.method
        http_version = request.scope["http_version"]

        API_LOGGER.info(
            f"{client_host}:{client_port} - {http_method} {url} HTTP/{http_version} {status_code}",
            http={
                "url": str(request.url),
                "status_code": status_code,
                "method": http_method,
                "version": http_version,
            },
            network={"client": {"ip": client_host, "port": client_port}},
            duration=process_time,
        )

    return response
