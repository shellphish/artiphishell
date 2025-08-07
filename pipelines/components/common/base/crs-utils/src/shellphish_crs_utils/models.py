from typing import Annotated, List, Union
from pydantic import BaseModel, Field, StringConstraints

PDT_ID = Union[str, int]
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

class CrashingCommitReport(BaseModel):
    cp_source: str
    crashing_commit: Annotated[str, SHA1_CONSTRAINTS]
    sanitizer_ids: List[Annotated[str, ID_CONSTRAINTS]]
    crash_report_id: PDT_ID
    crash_id: PDT_ID
    harness_id: PDT_ID

class RunPovResult(BaseModel):
    pov: dict
    time_start: float
    time_end: float
    time_taken: float
    cid: str
    exitcode: int
    stdout: bytes
    stderr: bytes
    
class RepresentativeCrashingInputMetadata(BaseModel):
    target_id: PDT_ID
    harness_info_id: PDT_ID
    cp_harness_name: str
    cp_harness_id: str
    cp_harness_source_path: str
    cp_harness_binary_path: str
    run_pov_result: RunPovResult
    original_crash_id: PDT_ID
    sanitizer_history: List[List[str]]
    consistent_sanitizers: List[str]
    inconsistent_sanitizers: List[str]

class PatchVerificationRequest(BaseModel):
    target_id: PDT_ID
    harness_id: PDT_ID
    patch_id: PDT_ID
    crashing_commit_sha: Annotated[str, SHA1_CONSTRAINTS]
    crashing_commit_report_id: PDT_ID
    crash_report_representative_crashing_input_id: PDT_ID
    sanitizer_id: str

class PatchVerificationResult(BaseModel):
    patch_id: PDT_ID
    still_crashing: bool