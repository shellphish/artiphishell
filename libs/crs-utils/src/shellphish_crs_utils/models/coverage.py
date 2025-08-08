from collections import namedtuple
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple, TypeAlias, Union
from pydantic import BaseModel, Field
from shellphish_crs_utils.models.base import ShellphishBaseModel
from shellphish_crs_utils.models.indexer import FUNCTION_INDEX_KEY, FunctionIndex

# THIS IS EXTREMELY PERFORMANCE CRITICAL for coverage collection
# DO NOT change this to a pydantic model, it doesn't benefit much and it's SIGNIFICANTLY slower
@dataclass
class CoverageLine:
    line_number: int
    count_covered: Optional[int] = None
    code: Optional[str] = None

    @property
    def count(self):
        return self.count_covered

    @count.setter
    def count(self, value):
        self.count_covered = value

    def can_be_covered(self):
        return self.count_covered is not None

    def as_tuple(self):
        return (self.line_number, self.count_covered, self.code)

class SeedCoverageExitStatus(Enum):
    CRASH =     "crash"
    TIMEOUT =   "timeout"
    SUCCESS =   "success"
    UNKNOWN =   "unknown"

LinesCoverage: TypeAlias        = List[     CoverageLine]
FileCoverage: TypeAlias         = Tuple[    Union[Path, str],   LinesCoverage]
FileCoverageMap: TypeAlias      = Dict[     Union[Path, str],   LinesCoverage]
FunctionCoverage: TypeAlias     = Tuple[    FUNCTION_INDEX_KEY, LinesCoverage]
FunctionCoverageMap: TypeAlias  = Dict[     FUNCTION_INDEX_KEY, LinesCoverage]