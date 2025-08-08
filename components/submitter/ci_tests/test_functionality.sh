#!/bin/bash
set -e

pip install uv
uv sync

# Run the tests
uv run pytest
