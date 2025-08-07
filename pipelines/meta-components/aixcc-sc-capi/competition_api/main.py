import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from structlog.stdlib import get_logger
from vyper import v

from competition_api.config import init_vyper
from competition_api.cp_registry import CPRegistry
from competition_api.endpoints import GPRouter, HealthRouter, VDSRouter
from competition_api.logging import logging_middleware, setup_logging

LOGGER = get_logger()

AIXCC_API_VERSION = os.environ.get("AIXCC_API_VERSION", "0.0.0")

tags_metadata = [
    {
        "name": "health",
        "description": "This endpoint will be used to check health of API.",
    },
    {
        "name": "submission",
        "description": "This endpoint will be used to submit VD and GP.",
    },
]


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_vyper()
    setup_logging()

    if not v.get_bool("mock_mode"):
        # initialize cp registry
        CPRegistry.instance()

    yield


app = FastAPI(
    title=f"cAPI v{AIXCC_API_VERSION} - AIXCC Competition API",
    lifespan=lifespan,
    version=AIXCC_API_VERSION,
    description="""
# AIxCC Competition API

## API Limitations

* Submitted POV binary input blobs must be 2MiB or smaller, before base64.
* Submitted patch files must be 100KiB or smaller, before base64.
* Submitted patch files may only modify .c, .h, .in, and .java files.
""",
    terms_of_service="https://aicyberchallenge.com/terms-condition/",
    openapi_tags=tags_metadata,
    contact={
        "name": "AIXCC",
        "url": "https://aicyberchallenge.com/faqs/",
    },
)

app.middleware("http")(logging_middleware)

for router in [GPRouter, VDSRouter, HealthRouter]:
    app.include_router(router)
