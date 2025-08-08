from typing import Annotated, List
from pydantic import StringConstraints, Field
from shellphish_crs_utils.models.base import ShellphishBaseModel
from shellphish_crs_utils.models.constraints import PDT_ID, ID_CONSTRAINTS

SHA1_REGEX = r"[0-9a-f]{40}"
SHA1_CONSTRAINTS = StringConstraints(
    strip_whitespace=True,
    to_upper=True,
    pattern=SHA1_REGEX,
    max_length=40,
    min_length=40,
)


class CrashingCommitReport(ShellphishBaseModel):
    cp_source: str = Field(
        description="The challenge project source linked to crashing commit"
    )
    crashing_commit: Annotated[str, SHA1_CONSTRAINTS] = Field(
        description="The crashing commit sha"
    )
    sanitizer_ids: List[Annotated[str, ID_CONSTRAINTS]] = Field(
        description="The sanitizer ids in the crash"
    )
    crash_report_id: PDT_ID = Field(description="The pydatatask pov report id")
    crash_id: PDT_ID = Field(description="The pydatatask crashing input id")
    harness_id: PDT_ID = Field(description="The pydatatask harness info id")


class PatchVerificationRequest(ShellphishBaseModel):
    project_id: PDT_ID = Field(description="The pydatatask target id")
    harness_id: PDT_ID = Field(description="The pydatatask harness id")
    patch_id: PDT_ID = Field(description="The pydatatask patch id")
    crashing_commit_sha: Annotated[str, SHA1_CONSTRAINTS] = Field(
        description="The crashing commit sha"
    )
    crashing_commit_report_id: PDT_ID = Field(
        description="The pydatatask crashing commit id"
    )
    crash_report_representative_crashing_input_id: PDT_ID = Field(
        description="The pydatatask representative crashing input id"
    )
    sanitizer_id: str = Field(
        description="The sanitizer id reported for triggering the crash"
    )


class PatchVerificationResult(ShellphishBaseModel):
    patch_id: PDT_ID = Field(description="The pydatatask patch id")
    still_crashing: bool = Field(description="Whether the patch still crashes")
