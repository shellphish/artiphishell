from pydantic import Field
from typing import Optional
from shellphish_crs_utils.models.base import ShellphishBaseModel
from shellphish_crs_utils.models.constraints import PDT_ID

class PatchMetaData(ShellphishBaseModel):
    """
    Metadata for a patch.
    """
    patcher_name: str = Field(description="The name of the patcher")
    total_cost: float = Field(description="The total cost of the patch")
    poi_report_id: Optional[str] = Field(description="The id of poi report", default=None)
    pdt_harness_info_id: Optional[str] = Field(description="The id of harness info", default=None)
    pdt_project_id: Optional[str] = Field(description="The id of oss fuzz project", default=None)
    pdt_project_name: Optional[str] = Field(description="The name of the oss fuzz project", default=None)
    build_request_id: Optional[PDT_ID] = Field(description="The id of the build request", default=None)


class PatchBypassRequestMeta(ShellphishBaseModel):
    """
    Metadata for a patch bypass request.
    """
    project_id: str = Field(description="The id of the project")
    harness_id: str = Field(description="The id of the harness")
    sanitizer_name: Optional[str] = Field(description="The id of the sanitizer")
    patch_id: str = Field(description="The id of the patch we just created")
    mitigated_poi_report_id: str = Field(description="The id of the poi report mitigated by this patch")
    patcher_name: str = Field(description="The name of the patcher that asked for this bypass")
    build_request_id: str = Field(description="The id of the build request")
    patch_description: Optional[str] = Field(description="The description of the patch we just created", default=None)
    sarif_id: Optional[str] = Field(description="The id of the sarif report generated for this patch", default=None)


class BypassResultMeta(ShellphishBaseModel):
    """
    Metadata for a patch bypass result.
    """
    patch_id: str = Field(description="The id of the patch that was bypass by discoguy")
    summary: str = Field(description="The summary of how the patch was bypassed")
    crashing_input_id: Optional[str] = Field(description="The id of the new crashing input that bypassed the patch", default=None)

class PatchBucketRanking(ShellphishBaseModel):
    bucket: list[str] = Field(description="List of patch ids in the bucket")
    patch_info: dict[str, float] = Field(description="Dictionary of patch ids and their scores")
    poi_report_ids: list[str] = Field(description="List of POI report IDs associated with the patches in the bucket")
    ranks: list[str] = Field(description="Sorted list of patch ids in the order of their scores")
    timestamp: int = Field(description="Timestamp of the bucket ranking")

class PatchRankings(ShellphishBaseModel):
    buckets: list[PatchBucketRanking] = Field(description="List of patch buckets with their rankings")
    timestamp: int = Field(description="Timestamp of the rankings file being created")