import uuid
from typing import Annotated

from pydantic import UUID4, Base64Str, BaseModel, Field
from pydantic.functional_validators import AfterValidator

from .examples import EXAMPLE_B64
from .types import FeedbackStatus
from .validators import max_size

KiB_100 = 102400


class GPSubmission(BaseModel):
    cpv_uuid: UUID4
    data: Annotated[Base64Str, AfterValidator(max_size(KiB_100))] = Field(
        description=(
            "Base64'd patch file.  Maximum allowed size is 100KiB before base64.  Any "
            "modification to files not ending in .c, .h, .in, or .java will cause the "
            "patch to be rejected."
        )
    )

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "cpv_uuid": str(uuid.uuid4()),
                    "data": EXAMPLE_B64,
                }
            ]
        }
    }


class GPResponse(BaseModel):
    status: FeedbackStatus
    patch_size: int
    gp_uuid: UUID4

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "status": str(FeedbackStatus.ACCEPTED),
                    "patch_size": 1024,
                    "gp_uuid": str(uuid.uuid4()),
                }
            ]
        }
    }


class GPStatusResponse(BaseModel):
    status: FeedbackStatus
    gp_uuid: UUID4

    model_config = {
        "json_schema_extra": {
            "examples": [
                {"status": str(FeedbackStatus.ACCEPTED), "gp_uuid": str(uuid.uuid4())}
            ]
        }
    }
