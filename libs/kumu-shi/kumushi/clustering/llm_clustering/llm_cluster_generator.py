import logging
from typing import List
from pathlib import Path

import jinja2
from ..cluster_generator import ClusterGenerator
from ...data import Program, PoICluster, PoISource
from .cluster_agent import ClusterAgent

_l = logging.getLogger(__name__)

class LLMClusterGenerator(ClusterGenerator):
    def __init__(self, program: Program, max_cluster_size: int = 8, max_clusters: int = 10, poi_clusters: List[PoICluster] | None = None):
        super().__init__(program, max_cluster_size=max_cluster_size, max_clusters=max_clusters)
        self._input_clusters = poi_clusters
        self.valid_funcs = self._collect_valid_functions()

    def _collect_valid_functions(self):
        valid_funcs = set()
        for poi_cluster in self._input_clusters:
            for poi in poi_cluster.pois:
                if poi.function.name:
                    valid_funcs.add(poi.function.name)

        return valid_funcs

    def _retrive_context_report(self):
        # get the potential asan report
        asan_report = ""
        if self._program and self._program.poi_report and 'asan_report_data' in self._program.poi_report.additional_information:
            cleaned_report = self._program.poi_report.additional_information['asan_report_data'].get('cleaned_report', None)
            if cleaned_report:
                asan_report = cleaned_report

        complete_context_report = ""
        for index, poi_cluster in enumerate(self._input_clusters):
            query_path = Path(__file__).resolve().parent / 'prompts' / 'context_report.j2'
            with open(query_path, 'r') as f:
                template = jinja2.Template(f.read())
            context_report = template.render(
                pois=poi_cluster.pois,
                cluster_id=index,
                asan_report=asan_report,
            )
            complete_context_report += context_report.rstrip() + "\n"
        return complete_context_report

    def analyze(self):
        context_report = self._retrive_context_report()
        cluster_agent = ClusterAgent(
            init_context=context_report,
            project_language=self._program.language,
            valid_functions=self.valid_funcs,
        )
        cluster_agent.use_web_logging_config(clear=True)
        failed_llm = True
        res = None
        for i in range(3):
            try:
                res = cluster_agent.invoke()
                failed_llm = False
                break
            except Exception as e:
                _l.error("failed to invoke LLM Cluster Agent, retrying...", exc_info=True)
                failed_llm = True
                continue

        if failed_llm:
            _l.error("LLM Cluster Agent failed to invoke after 3 attempts!")
            self.clusters = []
            return

        if not res or not res.value:
            _l.error("LLM Cluster Agent failed to generate clusters!")
            return

        func_names = res.value["cluster"]
        reason = res.value["description"]

        pois = []
        for func_name in func_names:
            # assume all current poi clusters are singleton clusters
            for poi_cluster in self._input_clusters:
                poi = poi_cluster.pois[0]
                if poi.function.name == func_name or poi.function.name == f"OSS_FUZZ_{func_name}":
                    pois.append(poi)
                    break
            else:
                _l.warning(f"Function {func_name} not found in any PoI clusters, skipping.")

        if pois:
            self.clusters = [PoICluster.from_pois(pois, source=PoISource.LLM_FOUND, reasoning=reason)]
            _l.info(f"Generated {len(self.clusters)} clusters using LLM clustering.")
        else:
            self.clusters = []