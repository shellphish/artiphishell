"""Code block representation model."""

from .base import BaseObject

from typing import Dict, Optional, List, Any
from pydantic import Field
import uuid

from .filter import FilterResult

from shellphish_crs_utils.models.indexer import FunctionIndex, FUNCTION_INDEX_KEY

class CodeBlock(BaseObject):
    """Represents a block of code with metadata for filtering and prioritization."""

    function_key: FUNCTION_INDEX_KEY = Field(description="Function key from indexer")
    
    # Core information from function index
    function_info: FunctionIndex = Field(description="Function information from indexer")

    unique_id: str = Field(description="Unique identifier for this code block", default_factory=lambda: str(uuid.uuid4()))

    def __hash__(self) -> int:
        """Generate a hash based on the unique_id only.
        This makes the type hashable regardless of whether its members are hashable."""
        return hash(self.unique_id)
    
    def __eq__(self, other: object) -> bool:
        """Equality comparison based on unique_id.
        This ensures that hash-based containers work correctly."""
        if not isinstance(other, CodeBlock):
            return NotImplemented
        return self.unique_id == other.unique_id

    @property
    def funcname(self) -> str:
        return self.function_info.funcname

    @property
    def signature(self) -> str:
        return self.function_info.signature
    
    @property
    def func_calls_in_func_with_fullname(self) -> List[str]:
        return self.function_info.func_calls_in_func_with_fullname
    
    # Analysis metadata
    priority_score: Optional[float] = Field(
        default=None,
        description="Priority score for this block, calculated from filter results"
    )

    metadata: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Metadata for this block, keyed by filter name"
    )
    
    # Filter results - keyed by filter name
    filter_results: Dict[str, FilterResult] = Field(
        default_factory=dict,
        description="Results from each filter pass, keyed by filter name"
    ) 