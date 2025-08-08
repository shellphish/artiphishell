"""Tests for input loaders."""

import json
import pytest
import shutil
from pathlib import Path

from shellphish_crs_utils.models.indexer import FunctionIndex
from src.input.ingester import FunctionIndexIngester

@pytest.fixture
def test_data_copy(tmp_path: Path, test_data_root: Path) -> Path:
    """Create a copy of test data in a temporary directory."""
    # Copy the samples directory to temp
    src_dir = test_data_root / "samples"
    dst_dir = tmp_path / "samples"
    shutil.copytree(src_dir, dst_dir)
    return tmp_path

def test_ingester_creation(test_data_copy):
    """Test basic ingester creation."""
    ingester = FunctionIndexIngester(index_dir=test_data_copy)
    assert ingester.index_dir == test_data_copy

def test_load_function_index(test_data_copy, test_data_root):
    """Test loading a single function index file."""
    ingester = FunctionIndexIngester(index_dir=test_data_copy)
    file_path = test_data_copy / "samples/FUNCTION/func_a_mock_vp.c_0bc8fb4d662291309fbaf041aa1868a2.json"
    
    index = ingester.load_function_index(file_path)
    assert isinstance(index, FunctionIndex)
    assert index.funcname == "func_a"
    assert "void func_a()" in index.code

def test_ingest_directory(test_data_copy):
    """Test ingesting all files from a directory."""
    ingester = FunctionIndexIngester(index_dir=test_data_copy)
    
    code_blocks = ingester.ingest_directory()
    assert len(code_blocks) == 3  # We know there are 3 functions in the test data
    
    # Check that we got all functions
    function_names = {block.function_info.funcname for block in code_blocks}
    assert function_names == {"func_a", "func_b", "main"}

def test_invalid_json(test_data_copy):
    """Test handling of invalid JSON files."""
    # Create invalid JSON file
    invalid_file = test_data_copy / "samples/FUNCTION/invalid.json"
    invalid_file.write_text("not valid json")
    
    ingester = FunctionIndexIngester(index_dir=test_data_copy)
    code_blocks = ingester.ingest_directory()
    
    # Should still get the valid files
    assert len(code_blocks) == 3

def test_missing_directory(tmp_path):
    """Test handling of missing directories."""
    ingester = FunctionIndexIngester(index_dir=tmp_path)
    
    with pytest.raises(FileNotFoundError):
        ingester.ingest_directory()

def test_empty_directory(tmp_path):
    """Test handling of empty directories."""
    # Create empty directory structure
    function_dir = tmp_path / "samples" / "FUNCTION"
    function_dir.mkdir(parents=True)
    
    ingester = FunctionIndexIngester(index_dir=tmp_path)
    code_blocks = ingester.ingest_directory()
    
    assert len(code_blocks) == 0 