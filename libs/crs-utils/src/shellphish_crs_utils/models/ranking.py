from typing import List, Dict, Optional
from pydantic import Field

from shellphish_crs_utils.models.base import ShellphishBaseModel
from shellphish_crs_utils.models.indexer import FUNCTION_INDEX_KEY, FunctionIndex

class RankedFunction(ShellphishBaseModel):
    rank_index: int
    function_index_key: FUNCTION_INDEX_KEY = Field(description="Function signature defined by the function indexer convention (filename:start_line:start_column::signature)")
    priority_score: float = Field(description="Priority score")

    funcname: str = Field(description="The name of the function")
    full_funcname: str = Field(description="The full name of the function (class_name::function_name if applicable)")
    func_return_type: str = Field(description="The return type of the function")
    signature: Optional[FUNCTION_INDEX_KEY] = Field(description="Function signature defined by the function indexer convention (filename:start_line:start_column::signature)")
    filename: str = Field(description="The name of the file containing the function")
    class_name: Optional[str] = Field(description="The name of the class containing the function", default=None)
    package: Optional[str] = Field(description="The package of the function (Java Only)", default=None)

    metadata: Dict = Field(description="Metadata")
    weights: Optional[Dict] = Field(description="Weights")

    @classmethod
    def from_function_index(cls, function_index: FunctionIndex, **kwargs) -> "RankedFunction":
        return cls(
            function_index_key=kwargs.pop("function_index_key", function_index.signature),
            funcname=function_index.funcname,
            full_funcname=function_index.full_funcname,
            func_return_type=function_index.func_return_type,
            signature=function_index.signature,
            filename=function_index.filename,
            class_name=function_index.class_name,
            package=function_index.package,
            **kwargs
        )

class CodeSwipeRanking(ShellphishBaseModel):
    ranking: List[RankedFunction] = Field(description="Ranking of functions")