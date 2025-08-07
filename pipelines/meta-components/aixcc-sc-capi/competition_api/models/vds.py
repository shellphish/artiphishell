import uuid
from typing import Annotated

from pydantic import UUID4, Base64Bytes, BaseModel, Field, StringConstraints
from pydantic.functional_validators import AfterValidator

from competition_api.models.examples import (
    EXAMPLE_B64,
    EXAMPLE_HARNESS,
    EXAMPLE_SANITIZER,
    EXAMPLE_SHA1,
)
from competition_api.models.types import FeedbackStatus
from competition_api.models.validators import max_size

ID_REGEX = r"^id_[0-9]+$"
ID_CONSTRAINTS = StringConstraints(strip_whitespace=True, pattern=ID_REGEX)

SHA1_REGEX = r"[0-9a-f]{40}"
SHA1_CONSTRAINTS = StringConstraints(
    strip_whitespace=True,
    to_upper=True,
    pattern=SHA1_REGEX,
    max_length=40,
    min_length=40,
)

MiB_2 = 2097152


class POU(BaseModel):
    commit_sha1: Annotated[str, SHA1_CONSTRAINTS]
    sanitizer: Annotated[str, ID_CONSTRAINTS]

    model_config = {
        "json_schema_extra": {
            "examples": [{"commit_sha1": EXAMPLE_SHA1, "sanitizer": EXAMPLE_SANITIZER}]
        }
    }


class POV(BaseModel):
    harness: Annotated[str, ID_CONSTRAINTS]
    data: Annotated[Base64Bytes, AfterValidator(max_size(MiB_2))] = Field(
        description="POV input binary blob in base64.  Maximum allowed size is 2MiB before base64."
    )

    model_config = {
        "json_schema_extra": {
            "examples": [{"harness": EXAMPLE_HARNESS, "data": EXAMPLE_B64}]
        }
    }


class VDSubmission(BaseModel):
    cp_name: str
    pou: POU
    pov: POV

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "cp_name": "linux kernel",
                    "pou": {
                        "commit_sha1": EXAMPLE_SHA1,
                        "sanitizer": EXAMPLE_SANITIZER,
                    },
                    "pov": {"harness": EXAMPLE_HARNESS, "data": EXAMPLE_B64},
                }
            ]
        }
    }


class VDSResponse(BaseModel):
    status: FeedbackStatus
    cp_name: str
    vd_uuid: UUID4

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "status": str(FeedbackStatus.ACCEPTED),
                    "cp_name": "linux kernel",
                    "vd_uuid": str(uuid.uuid4()),
                }
            ]
        }
    }


class VDSStatusResponse(BaseModel):
    status: FeedbackStatus
    vd_uuid: UUID4
    cpv_uuid: UUID4 | None = Field(
        description="This is only provided if the VDS is accepted."
    )

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "status": str(FeedbackStatus.ACCEPTED),
                    "vd_uuid": str(uuid.uuid4()),
                    "cpv_uuid": str(uuid.uuid4()),
                }
            ]
        }
    }
