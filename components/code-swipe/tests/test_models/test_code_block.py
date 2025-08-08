"""Tests for code block model."""

import pytest
from pathlib import Path

from shellphish_crs_utils.models.indexer import FunctionIndex
from src.models.code_block import CodeBlock
from src.models.filter_result import FilterResult

@pytest.fixture
def sample_function_index() -> FunctionIndex:
    """Create a sample function index for testing."""
    return FunctionIndex(
        funcname="test_func",
        full_funcname="test_func",
        func_return_type="void",
        arguments=["int x", "char* y"],
        local_variables=["int temp"],
        global_variables=[],
        func_calls_in_func_with_fullname=[],
        filepath=Path("src/test.c"),
        filename="test.c",
        hash="abc123",
        code="void test_func(int x, char* y) { int temp; }",
        signature="void test_func(int, char*)",
        start_line=1,
        end_line=3,
        start_offset=0,
        end_offset=100,
        start_column=1,
        end_column=1
    )

def test_code_block_creation(sample_function_index):
    """Test basic code block creation."""
    block = CodeBlock(function_info=sample_function_index)
    
    assert block.function_info == sample_function_index
    assert block.priority_score is None
    assert block.filter_results == {}

def test_code_block_with_filter_results(sample_function_index):
    """Test code block with filter results."""
    block = CodeBlock(function_info=sample_function_index)
    
    # Add some filter results
    result1 = FilterResult(weight=0.5, metadata={"reason": "test"})
    result2 = FilterResult(weight=0.8, metadata={"matches": ["pattern1"]})
    
    block.filter_results["filter1"] = result1
    block.filter_results["filter2"] = result2
    
    assert len(block.filter_results) == 2
    assert block.filter_results["filter1"].weight == 0.5
    assert block.filter_results["filter2"].metadata["matches"] == ["pattern1"]

def test_code_block_priority_score(sample_function_index):
    """Test setting priority score."""
    block = CodeBlock(function_info=sample_function_index)
    
    block.priority_score = 0.75
    assert block.priority_score == 0.75 