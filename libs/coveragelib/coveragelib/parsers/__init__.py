import abc
from pathlib import Path
from typing import Set
from coveragelib import Parser
from shellphish_crs_utils.models.coverage import FileCoverageMap
from shellphish_crs_utils.models.symbols import SourceLocation
from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject

class FunctionCoverageParser(Parser, abc.ABC):
    HAS_VALUE_PARSER = True

    @abc.abstractmethod
    def parse_values(self, oss_fuzz_project: OSSFuzzProject, coverage_path: Path) -> Set[SourceLocation]:
        raise NotImplementedError

class LineCoverageParser(Parser, abc.ABC):
    HAS_VALUE_PARSER = True

    @abc.abstractmethod
    def parse_values(self, oss_fuzz_project: OSSFuzzProject, coverage_path: Path) -> FileCoverageMap:
        raise NotImplementedError

from .function_coverage import C_FunctionCoverageParser_Profraw, Java_FunctionCoverageParser_Jacoco
from .line_coverage import C_LineCoverageParser_LLVMCovHTML, Java_LineCoverageParser_Jacoco
from .calltrace_coverage import C_Calltrace_PinTracer, Java_Calltrace_Yajta, C_Indirect_PinTracer