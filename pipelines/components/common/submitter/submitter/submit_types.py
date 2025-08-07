import time
from typing import Union, List

from pydantic import BaseModel, root_validator, UUID4

from models.vds import VDSubmission, VDSResponse, VDSStatusResponse
from models.gp import GPSubmission, GPResponse, GPStatusResponse
# from models.types import FeedbackStatus

class Commit(BaseModel):
    crash_id: str
    cp_source: str
    crash_report_id: str
    crashing_commit: str
    crashing_commit_id: str
    sanitizer_ids: List[str]
    harness_id: str

class Patch(BaseModel):
    data: bytes
    cpv_uuid: UUID4

class SubmitState(BaseModel):
    submission: Union[VDSubmission, GPSubmission]
    response: Union[VDSResponse, VDSStatusResponse, GPResponse, GPStatusResponse, None]
    crashing_commit_id: str
    # unix_time_created: int = int(time.time())
    # unix_time_done: int = int(time.time())

    # class Config:
        # validate_assignment = True
    
    # @root_validator(skip_on_failure=True)
    # def time_validator(cls, values):
        # if getattr(values["response"], "status", None) == FeedbackStatus.ACCEPTED:
            # return values
# 
        # values["unix_time_done"] = int(time.time())
        # return values