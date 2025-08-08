"""Tests for filter framework."""

import pytest
from typing import List

from src.framework.filter_framework import FilterFramework
from src.models.filter import FilterPass, FilterResult
from src.models.code_block import CodeBlock
from pydantic import Field

class TestFilter(FilterPass):
    """Test filter implementation."""
    
    weight: float = Field(description="Weight of the filter")
    
    def process(self, code_block: CodeBlock) -> FilterResult:
        """Process a code block."""
        return FilterResult(weight=self.weight)

@pytest.fixture
def framework() -> FilterFramework:
    """Create a test framework instance."""
    return FilterFramework()

@pytest.fixture
def test_filters() -> List[FilterPass]:
    """Create a list of test filters."""
    return [
        TestFilter(name="filter1", weight=0.3),
        TestFilter(name="filter2", weight=0.5),
        TestFilter(name="filter3", weight=0.8)
    ]

@pytest.fixture
def sample_code_block(sample_function_index) -> CodeBlock:
    """Create a sample code block."""
    return CodeBlock(function_info=sample_function_index)

def test_framework_creation(framework):
    """Test basic framework creation."""
    assert framework.registered_passes == {}
    assert framework.execution_order == []
    assert framework.global_config == {}

def test_register_filter(framework, test_filters):
    """Test registering filters."""
    # Register filters in order
    for filter_pass in test_filters:
        framework.register_pass(filter_pass)
    
    assert len(framework.registered_passes) == 3
    assert framework.execution_order == ["filter1", "filter2", "filter3"]

def test_register_filter_with_position(framework, test_filters):
    """Test registering filters with specific positions."""
    # Register filters in reverse order
    framework.register_pass(test_filters[2], position=0)  # filter3 first
    framework.register_pass(test_filters[1], position=0)  # filter2 first
    framework.register_pass(test_filters[0], position=0)  # filter1 first
    
    assert framework.execution_order == ["filter1", "filter2", "filter3"]

def test_process_blocks(framework, test_filters, sample_code_block):
    """Test processing blocks through filters."""
    # Register filters
    for filter_pass in test_filters:
        framework.register_pass(filter_pass)
    
    # Process a single block
    blocks = framework.process_blocks([sample_code_block])
    block = blocks[0]
    
    assert len(block.filter_results) == 3
    assert block.filter_results["filter1"].weight == 0.3
    assert block.filter_results["filter2"].weight == 0.5
    assert block.filter_results["filter3"].weight == 0.8

def test_disabled_filter(framework, test_filters, sample_code_block):
    """Test that disabled filters are skipped."""
    # Register filters with one disabled
    test_filters[1].enabled = False
    for filter_pass in test_filters:
        framework.register_pass(filter_pass)
    
    # Process a block
    blocks = framework.process_blocks([sample_code_block])
    block = blocks[0]
    
    assert len(block.filter_results) == 2
    assert "filter2" not in block.filter_results
    assert block.filter_results["filter1"].weight == 0.3
    assert block.filter_results["filter3"].weight == 0.8

def test_calculate_priority_scores(framework, test_filters, sample_code_block):
    """Test priority score calculation."""
    # Register and run filters
    for filter_pass in test_filters:
        framework.register_pass(filter_pass)
    
    blocks = framework.process_blocks([sample_code_block])
    blocks = framework.calculate_priority_scores(blocks)
    
    # Priority should be sum of weights (0.3 + 0.5 + 0.8 = 1.6)
    assert blocks[0].priority_score == 1.6

def test_filter_error_handling(framework, sample_code_block):
    """Test handling of filter errors."""
    class ErrorFilter(FilterPass):
        def process(self, code_block: CodeBlock) -> FilterResult:
            raise ValueError("Test error")
    
    # Register error filter and good filter
    framework.register_pass(ErrorFilter(name="error_filter"))
    framework.register_pass(TestFilter(name="good_filter", weight=0.5))
    
    # Process should continue despite error
    blocks = framework.process_blocks([sample_code_block])
    block = blocks[0]
    
    assert len(block.filter_results) == 1
    assert "error_filter" not in block.filter_results
    assert "good_filter" in block.filter_results 