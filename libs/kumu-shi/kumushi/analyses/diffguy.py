import logging

from .analysis import Analysis
from .analysis import AnalysisWeight
from kumushi.data import PoI, PoICluster, PoISource
from kumushi.code_parsing import CodeFunction

_l = logging.getLogger(__name__)

class DiffGuyAnalysis(Analysis):
    NAME = "diffguy"
    ANALYSIS_WEIGHT = AnalysisWeight.WEIGHTLESS

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.has_git_info = bool(self.program.delta_mode)

    def retrive_pois(self) -> list[PoI]:
        collect_pois = []
        diffguy_func_keys = self.program.diffguy_funcs
        for func_key in diffguy_func_keys:
            if not func_key:
                continue
            code_function = self.program.code.load_function_data(func_key, self.program.source_root)
            if code_function is None:
                _l.info(f"Function {func_key} not found in code")
                continue
            collect_pois.append(
                PoI(function=code_function, crash_line_num=-1, crash_line=None,
                    sources=[PoISource.DIFFGUY], report=None)
            )
        return collect_pois

    def _analyze(self) -> list[PoICluster]:
        if not self.has_git_info:
            return []
        pois = self.retrive_pois()
        _l.info(f'diff guy report found {len(pois)} PoIs')
        clusters = [PoICluster.from_pois([p], source=PoISource.DIFFGUY) for p in pois]
        return clusters