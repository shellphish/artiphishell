"""Pytest configuration and fixtures."""

import json
import pytest
from pathlib import Path

from shellphish_crs_utils.models.indexer import FunctionIndex

@pytest.fixture
def test_data_root() -> Path:
    """Return path to test data directory."""
    return Path("test-data/clang_index.output_dir")

@pytest.fixture
def sample_function_index(test_data_root: Path) -> FunctionIndex:
    """Create a sample function index from real test data."""
    file_path = test_data_root / "samples/FUNCTION/func_a_mock_vp.c_0bc8fb4d662291309fbaf041aa1868a2.json"
    with open(file_path) as f:
        data = json.load(f)
        return FunctionIndex.model_validate(data) 