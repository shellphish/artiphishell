import os

from ..analysis import Analysis, AnalysisWeight
from .aurora_ranker import AuroraRanker
from kumushi.data.poi import PoI, PoICluster, PoISource, CodeFunction
from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject

from pathlib import Path
import tempfile
import logging

_l = logging.getLogger(__name__)


class AuroraAnalysis(Analysis):
    NAME = "aurora"
    ANALYSIS_WEIGHT = AnalysisWeight.HEAVY
    TIMEOUT = 20*60 # 15 minutes
    REQUIRES_NEW_PROGRAM = True

    def _analyze(self) -> list[PoICluster]:
        if not self.program.crashing_input_dir:
            _l.info("Crashing input directory is not set, skipping Aurora analysis.")
            return []
        aurora_ranker = AuroraRanker( self.program, sanitizer=self.program.sanitizer_string, crashing_input=None,
                                     crashing_input_dir=self.program.crashing_input_dir,
                                     fuzzing_time=180, harness_name=self.program.harness_name)
        sorted_func_score, sorted_func_to_num = aurora_ranker.rank()
        _l.info(f"Aurora analysis found {len(sorted_func_score)} functions. Save all the pois that has score > 0.85")
        for func_key, score in sorted_func_score.items():
            if score < 0.85:
                continue
            code_func = self.program.code.load_function_data(func_key, self.program.source_root)
            if code_func is None:
                continue
            poi = PoI(sources=[PoISource.AURORA], function=code_func)
            poi_cluster = PoICluster(pois=[poi], source=PoISource.AURORA)
            self.poi_clusters.append(poi_cluster)
        _l.info(f"Aurora analysis found {len(self.poi_clusters)} PoIs.")
        _l.info(f"Aurora analysis found {self.poi_clusters}")
        # tempdir.cleanup()
        return self.poi_clusters
