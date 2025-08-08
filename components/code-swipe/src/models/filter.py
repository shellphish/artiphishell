"""Filter pass and result models."""

from abc import ABC, abstractmethod
from typing import Dict, TYPE_CHECKING
from pydantic import Field

from .base import BaseObject
from .filter_result import FilterResult


# Forward reference to avoid circular import
if TYPE_CHECKING:
    from src.models.code_block import CodeBlock

class FilterPass(BaseObject, ABC):
    """Abstract base class for implementing filter passes."""

    name: str = Field(description="Unique name of this filter pass")
    enabled: bool = Field(
        default=True,
        description="Whether this filter is currently enabled"
    )
    config: Dict = Field(
        default_factory=dict,
        description="Filter-specific configuration options"
    )
    is_negative: bool = Field(
        default=False,
        description="Whether the final weight should be negative"
    )

    @abstractmethod
    def apply(self, code_block: "CodeBlock") -> FilterResult:
        """Process a code block and return filter results.

        Args:
            code_block: The CodeBlock to analyze

        Returns:
            FilterResult containing the weight and metadata for this match
        """
        pass

    def pre_process_project(self, project: any, code_registry: any, metadata: Dict) -> None:
        """Process the entire project through this filter pass."""
        pass
