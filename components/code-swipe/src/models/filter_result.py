"""Filter result model."""

from typing import Dict, Any
from pydantic import Field

from .base import BaseObject

class FilterResult(BaseObject):
    """Result from running a filter on a single code block."""

    weight: float = Field(description="Weight/strength of the match (0.0 to 1.0)")
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional filter-specific metadata about the match"
    ) 