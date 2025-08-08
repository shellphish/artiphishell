from pathlib import Path
from typing import Dict
from typing import List

from QuickSeed.data.graph import CallGraphNode
from pydantic import BaseModel


class FileCoverage(BaseModel):
    file_name: str
    lines: Dict[int, bool]


class NodeCoverage(BaseModel):
    file_name: str
    lineno: int
    covered: bool


class TriageCoverage(BaseModel):
    seed_path: Path
    script_path: Path
    node_path: List[CallGraphNode]
    stuck_method_index: int
    harness_name: str
    harness_filepath: Path
