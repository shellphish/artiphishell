import logging
from collections import Counter

from kumushi.tracing.flexible_tracer import FlexibleTracer
from kumushi.analyses.analysis import Analysis, AnalysisWeight
from kumushi.data import PoI, PoISource, PoICluster

_l = logging.getLogger(__name__)


class CallTraceAnalysis(Analysis):
    """
    Gets PoIs ordered by a trace through the program, as well as the distance from the crashing function.
    """
    NAME = "call_trace"
    ANALYSIS_WEIGHT = AnalysisWeight.LIGHT
    TIMEOUT = 10*60
    REQUIRES_NEW_PROGRAM = True

    def __init__(self, *args, crashing_location_poi=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._crashing_func_name = crashing_location_poi.function.name if crashing_location_poi is not None else None
        self.poi_indices = []

    def _analyze(self):
        tracer = FlexibleTracer(self.program, analysis_name=self.NAME)
        ordered_pois = tracer.trace(self.program.crashing_input)
        if not ordered_pois:
            _l.error("No PoIs were found in the call trace! This is unexpected.")
            return []

        # poi_clusters = [PoICluster(pois=[poi], source=PoISource.CALL_TRACE) for poi in ordered_pois]
        self.poi_indices = [poi.function.function_index for poi in ordered_pois]
        return []

    def _rank_pois(self, ordered_pois: list[PoI]) -> list[PoI]:
        ordered_funcs = [poi.function.name for poi in ordered_pois][::-1]
        counted_funcs = Counter(ordered_funcs)
        for crash_idx, func_name in enumerate(ordered_funcs):
            if func_name == self._crashing_func_name:
                break
        else:
            _l.critical("Crashing function not found in trace! Defaulting to last function in trace.")
            return ordered_pois

        func_distance = {}
        # find the shortest distance from the crashing function for each unique func
        for idx, func_name in enumerate(ordered_funcs):
            if func_name not in func_distance:
                func_distance[func_name] = abs(crash_idx - idx)

        seen_pois = set()
        unique_pois = []
        for poi in ordered_pois:
            if poi not in seen_pois:
                seen_pois.add(poi)
                unique_pois.append(poi)

        # sort by distance, closest first, in a tie, most frequently called comes first
        unique_pois.sort(key=lambda poi: (func_distance.get(poi.function.name, 10000), -counted_funcs[poi.function.name]))
        _l.info("Call Trace Analysis found %d unique PoIs", len(unique_pois))
        return unique_pois[:5000]  # limit to 4000 PoIs



        # TODO: Ranking algorithm
        # Collect: Count of each function in trace
        #          Count shortest distance from crashing function name for each func
        # Sort function by distance, closest first, in a tie, most frequently called comes first
        # Uniquify functions and sort according to the above
        # Convert each to a POI Cluster
