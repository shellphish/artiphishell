import logging
from pathlib import Path
from typing import List, Optional
from enum import IntEnum

from ..code_parsing import CodeFunction

_l = logging.getLogger(__name__)

class PoISource(IntEnum):
    """
    The strict order of importance for PoI sources.
    """
    # the user (or user-like system) specified
    USER = 1
    # poi that was in the stack trace of the crash
    STACK_TRACE = 2
    # fuzzing-like previous work
    AURORA = 3
    # found in dyva report
    DYVA = 4
    # found in the diff guy report
    DIFFGUY = 5
    # found in a commit diff, where the commit is the buggy commit
    COMMIT = 6
    # static analysis found data deps
    VAR_DEP = 7
    # LLM found it
    LLM_FOUND = 8
    # in the ASAN free-trace for a UAF
    FREE_STACK = 9
    # in the total calls made during the crash
    CALL_TRACE = 10
    # merging
    MERGE = 11
    # unknown to kumushi
    UNKNOWN = 12


class PoI:
    def __init__(
        self,
        function: CodeFunction,
        crash_line_num: int = -1,
        crash_line: str | None = None,
        critical_variables: list[str] | None = None,
        sources: list[PoISource] | None = None,
        report: str | None = None,
        git_diff: str | None = None,
    ):
        self.function = function
        self.crash_line_num = crash_line_num
        self.crash_line = crash_line
        self.critical_variables = critical_variables or []
        self.sources = sources or [PoISource.UNKNOWN]
        self.report = report
        self.git_diff = git_diff

    @property
    def source(self):
        if len(self.sources) > 1:
            raise ValueError("Multiple sources for a PoI, reference the sources attribute instead.")
        return self.sources[0]

    @source.setter
    def source(self, source: PoISource):
        if len(self.sources) > 1:
            raise ValueError("Multiple sources for a PoI, reference the sources attribute instead.")
        self.sources = [source]

    def __str__(self):
        poi_str = f"<{self.__class__.__name__} file={self.function.file_path}, func={self.function}, line={self.crash_line_num}"
        if self.report and isinstance(self.report, str):
            poi_str += f", report={len(self.report)}"
        poi_str += ">"
        return poi_str

    def __repr__(self):
        return self.__str__()

    def __eq__(self, other):
        if not isinstance(other, PoI):
            return False

        return self.function == other.function and self.crash_line == other.crash_line

    def __hash__(self):
        return hash((self.function.file_path, self.function.start_line, self.function.end_line, self.crash_line))

    @staticmethod
    def merge(pois: list["PoI"]):
        sources = list(set([poi.source for poi in pois]))
        new_poi = PoI(None, sources=sources)
        # set attributes in the reverse order of priority for PoISource
        # this is to make sure that infomation from the most important source is kept
        for poi_src in list(PoISource):
            for poi in pois:
                if poi.source == poi_src:
                    # func
                    if new_poi.function is None:
                        new_poi.function = poi.function
                    else:
                        if not new_poi.function.name or not new_poi.function.file_path:
                            new_poi.function = poi.function

                    if new_poi.crash_line_num is None or new_poi.crash_line_num == -1:
                        new_poi.crash_line_num = poi.crash_line_num

                    if new_poi.crash_line is None or new_poi.crash_line_num == -1:
                        new_poi.crash_line = poi.crash_line

                    if not new_poi.critical_variables:
                        new_poi.critical_variables = poi.critical_variables

                    # report
                    if new_poi.report is None:
                        new_poi.report = ""
                    if isinstance(poi.report, str):
                        new_poi.report += poi.report + "\n"

        return new_poi

    def copy(self):
        return PoI(
            self.function.copy(),
            crash_line_num=self.crash_line_num,
            crash_line=self.crash_line,
            critical_variables=self.critical_variables.copy(),
            sources=self.sources,
            report=self.report,
            git_diff=self.git_diff,
        )

    def to_aicc_format(self):
        return {
            "source_location": {
                "relative_file_path": str(self.function.file_path),
                "function": self.function,
                "line_number": self.crash_line_num,
                "reason": self.report,
            }
        }


class PoICluster:
    def __init__(self, pois: List[PoI], reasoning: str | None = None, source: PoISource = PoISource.UNKNOWN):
        self.pois = pois
        self.reasoning = reasoning or ""
        self.source = source

    @classmethod
    def from_pois(cls, pois: list[PoI], source: PoISource = PoISource.UNKNOWN, reasoning: str | None = None) -> "PoICluster":
        return PoICluster(pois, source=source, reasoning=reasoning)

    def __str__(self):
        pois_funcs = ", ".join([poi.function.name for poi in self.pois if poi.function is not None])
        return f"<{self.__class__.__name__}: [{pois_funcs}]>"

    def __repr__(self):
        return self.__str__()

    def __eq__(self, other):
        if not isinstance(other, PoICluster):
            return False

        return self.pois == other.pois

    def __hash__(self):
        return hash(tuple(self.pois))

    @staticmethod
    def correct_relative_paths(poi_cluster: "PoICluster", source_root: Path) -> Optional["PoICluster"]:
        new_pois = []
        for poi in poi_cluster.pois:
            new_poi = poi.copy()
            if not poi.function or not poi.function.file_path:
                _l.critical(f"PoI %s has no file path set, cannot correct relative paths.", poi)
                return None

            new_poi.function.file_path = source_root / poi.function.file_path
            new_pois.append(new_poi)
        return PoICluster(new_pois, reasoning=poi_cluster.reasoning, source=poi_cluster.source)

    @staticmethod
    def rewrite_absolute_path(poi_cluster: "PoICluster", original_src_root: Path, new_src_root: Path) -> "PoICluster":
        new_pois = []
        for poi in poi_cluster.pois:
            new_poi = poi.copy()
            new_poi.function.file_path = new_src_root / poi.function.file_path.relative_to(original_src_root)
            new_pois.append(new_poi)
        return PoICluster(new_pois, reasoning=poi_cluster.reasoning, source=poi_cluster.source)
