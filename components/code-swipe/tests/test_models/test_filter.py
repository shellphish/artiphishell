"""Tests for filter models."""

import pytest
from typing import Dict, Any

from src.models.filter import FilterPass
from src.models.filter_result import FilterResult
from src.models.code_block import CodeBlock

class SampleFilter(FilterPass):
    """Sample filter implementation for testing."""
    
    def process(self, code_block: CodeBlock) -> FilterResult:
        """Sample process implementation."""
        return FilterResult(
            weight=0.5,
            metadata={"test": "data"}
        )

@pytest.fixture
def sample_filter() -> FilterPass:
    """Create a sample filter for testing."""
    return SampleFilter(name="test_filter")

def test_filter_result_creation():
    """Test basic filter result creation."""
    result = FilterResult(weight=0.75)
    
    assert result.weight == 0.75
    assert result.metadata == {}

def test_filter_result_with_metadata():
    """Test filter result with metadata."""
    metadata: Dict[str, Any] = {
        "reason": "suspicious function",
        "matches": ["pattern1", "pattern2"],
        "confidence": 0.9
    }
    
    result = FilterResult(weight=0.8, metadata=metadata)
    
    assert result.weight == 0.8
    assert result.metadata == metadata
    assert result.metadata["matches"] == ["pattern1", "pattern2"]

def test_filter_result_validation():
    """Test validation of filter result fields."""
    # Test invalid weight
    with pytest.raises(ValueError):
        FilterResult(weight="not a float")
    
    # Test invalid metadata type
    with pytest.raises(ValueError):
        FilterResult(weight=0.5, metadata="not a dict")

def test_filter_pass_creation(sample_filter):
    """Test basic filter pass creation."""
    assert sample_filter.name == "test_filter"
    assert sample_filter.enabled is True
    assert sample_filter.config == {}

def test_filter_pass_with_config(sample_filter):
    """Test filter pass with configuration."""
    config = {
        "threshold": 0.5,
        "patterns": ["pattern1", "pattern2"]
    }
    
    filter_pass = SampleFilter(
        name="test_filter",
        enabled=True,
        config=config
    )
    
    assert filter_pass.config == config
    assert filter_pass.config["threshold"] == 0.5

def test_filter_pass_disabled(sample_filter):
    """Test disabled filter pass."""
    filter_pass = SampleFilter(
        name="test_filter",
        enabled=False
    )
    
    assert filter_pass.enabled is False

def test_filter_pass_validation():
    """Test validation of filter pass fields."""
    # Test missing name
    with pytest.raises(ValueError):
        SampleFilter()
    
    # Test invalid enabled type
    with pytest.raises(ValueError):
        SampleFilter(name="test", enabled="not a bool")
    
    # Test invalid config type
    with pytest.raises(ValueError):
        SampleFilter(name="test", config="not a dict") 