import logging
from collections import defaultdict

from .analyses import Analysis
from .rca_mode import RCAMode
from kumushi.data import PoICluster, PoI, PoISource, Program
from kumushi.clustering import LLMClusterGenerator

_l = (logging.getLogger(__name__))

class PoIClusterRanker:
    def __init__(
        self,
        completed_analyses: list[Analysis],
        program: Program,
        mode=RCAMode.WEIGHTLESS,
        max_cluster_size: int = 5,
        max_clusters: int = 10,
        exclude_pois: list[PoICluster] = None,
    ):
        self._analyses = completed_analyses
        self._program = program
        self._mode = mode
        self._max_cluster_size = max_cluster_size
        self._max_clusters = max_clusters
        self._max_stack_trace = 4
        self._exclude_pois = exclude_pois or []

    def rank_poi_clusters(self) -> list[PoICluster]:
        all_poi_clusters = []
        for analysis in self._analyses:
            if analysis.ANALYSIS_WEIGHT <= self._mode:
                if analysis.NAME == "call_trace":
                    for poi_index in analysis.poi_indices:
                        function = self._program.code.load_function_data(poi_index, self._program.source_root)
                        if function:
                            poi = PoI(
                                function=function,
                                sources=[PoISource.CALL_TRACE],
                            )
                            analysis.poi_clusters.append(PoICluster.from_pois([poi], source=PoISource.CALL_TRACE))
                all_poi_clusters += analysis.poi_clusters
        _l.debug("Discovered %d PoIs for ranking", len(all_poi_clusters))

        filtered_poi_clusters = self._filter_poi_clusters(all_poi_clusters)
        _l.debug("Filtered out invalid PoIs. %d Remaining...", len(filtered_poi_clusters))
        # this will cause any pre-set clusters to be first in the queue
        poi_clusters, pois = self.expand_singleton_pois(filtered_poi_clusters)

        _l.debug("Expanded %d single PoIs that need clustering/ranking and %s completed clusters...", len(pois), len(poi_clusters))

        pois = self._reduce_stack_trace_pois(pois)
        _l.debug(f"Reduced stack trace PoIs to {self._max_stack_trace})")

        pois = self.merge_intersecting_pois(pois)
        _l.debug("Merged intersecting PoIs. %d singletons remaining...", len(pois))

        poi_clusters += self._cluster_pois_round_1(pois)
        _l.debug("Clustered %d PoIs. %d total clusters remaining...", len(pois), len(poi_clusters))

        poi_clusters = self._order_clusters(poi_clusters)
        _l.debug("Ordered %d PoI clusters", len(poi_clusters))
        # limit the pois
        if self._mode >= RCAMode.HEAVY:
            self._max_clusters = 20
        if len(poi_clusters) > self._max_clusters:
            _l.warning("Too many PoI clusters (%d). Reducing to %d", len(poi_clusters), self._max_clusters)
            poi_clusters = poi_clusters[:self._max_clusters]

        # second round of clustering
        poi_clusters = self._cluster_pois_round_2(poi_clusters)
        # filter it out again
        poi_clusters = self._filter_poi_clusters(poi_clusters)

        # remove the excluded pois
        if self._exclude_pois:
            _l.info("Excluding the following PoIs from the clusters %s", self._exclude_pois)
            remove_cnt = 0
            for cluster in self._exclude_pois:
                if cluster in list(poi_clusters):
                    remove_cnt += 1
                    poi_clusters.remove(cluster)
            _l.info(f"Successfully removed %d PoIs Clusters from the set", remove_cnt)

        if self._mode >= RCAMode.HEAVY:
            dyva_poi_cluster = None
            if self._program.dyva_report is not None and self._program.dyva_report.found_root_cause:
                root_cause_locations = self._program.dyva_report.root_cause_locations
                dyva_pois = []
                for root_cause in root_cause_locations:
                    function = self._program.code.load_function_data(root_cause.signature, self._program.source_root)
                    if function is None:
                        continue
                    dyva_pois.append(PoI(
                        function=function,
                        sources=[PoISource.DYVA],
                    ))
                dyva_poi_cluster = PoICluster.from_pois(dyva_pois, source=PoISource.DYVA)
            if dyva_poi_cluster is not None and len(dyva_poi_cluster.pois) > 0:
                _l.info(f"Adding DYVA PoI cluster with {len(dyva_poi_cluster.pois)} PoIs")
                poi_clusters.insert(1, dyva_poi_cluster)

        # filter once more!
        poi_clusters = self._filter_poi_clusters(poi_clusters)
        poi_clusters = self.merge_duplicate_clusters(poi_clusters)
        return poi_clusters

    def _cluster_pois_round_2(self, poi_clusters: list[PoICluster]) -> list[PoICluster]:
        """
        Do a second round of clustering to merge the clusters that are too small.
        """
        new_clusters = []
        # do more complicated LLM clustering
        if self._mode >= RCAMode.HEAVY:
            singleton_poi_clusters = [c for c in poi_clusters if len(c.pois) == 1]
            cluster_generator = LLMClusterGenerator(self._program, poi_clusters=singleton_poi_clusters)
            cluster_generator.analyze()
            new_clusters = cluster_generator.clusters + poi_clusters
        else:
            new_clusters = poi_clusters

        return new_clusters

    @staticmethod
    def expand_singleton_pois(poi_clusters: list[PoICluster]) -> tuple[list[PoICluster], list[PoI]]:
        real_clusters = []
        singleton_pois = []
        for poi_cluster in poi_clusters:
            if len(poi_cluster.pois) == 1:
                singleton_pois.append(poi_cluster.pois[0])
            else:
                real_clusters.append(poi_cluster)

        return real_clusters, singleton_pois

    @staticmethod
    def merge_duplicate_clusters(poi_clusters: list[PoICluster]) -> list[PoICluster]:
        """
        Merge duplicate clusters based on their PoIs.
        """
        clusters = []
        for p_clust in list(poi_clusters):
            funcs = set([poi.function.name for poi in p_clust.pois if poi.function])
            for other_p_clust in clusters:
                other_funcs = set([poi.function.name for poi in other_p_clust.pois if poi.function])
                if funcs == other_funcs:
                    break
            else:
                # if we didn't find any duplicates, add the cluster as is
                clusters.append(p_clust)

        return clusters

    @staticmethod
    def merge_intersecting_pois(pois: list[PoI]) -> list[PoI]:
        pois_by_function = defaultdict(list)
        new_pois = []
        for poi in pois:
            # TODO: what happens if there are overlapping names!??!
            if poi.function.name:
                pois_by_function[poi.function.name].append(poi)

        for func_name, pois in pois_by_function.items():
            if len(pois) == 1:
                new_pois.append(pois[0])
            else:
                # merge them
                new_pois.append(PoI.merge(pois))

        return new_pois

    def _filter_poi_clusters(self, poi_clusters: list[PoICluster]) -> list[PoICluster]:
        """
        Filter out the POIs that are not in the source code.
        """
        blacklist_funcs = {"LLVMFuzzerTestOneInput", "fuzz_target"}
        blacklist_paths = {"fuzz", "fuzzer", "fuzzing", "test", "tests"}

        if not poi_clusters:
            return []

        filtered_clusters = []
        for poi_cluster in poi_clusters:
            if not poi_cluster.pois:
                _l.warning("POI cluster %s is empty. Skipping it.", poi_cluster)
                continue

            try:
                poi_cluster = poi_cluster.correct_relative_paths(poi_cluster, self._program.source_root)
            except Exception as e:
                _l.error("Failed to correct relative paths due to %s", e)
                poi_cluster = None

            if poi_cluster is None:
                _l.warning("POI cluster is None after correcting relative paths. Skipping it.")
                continue

            first_poi = next(iter(poi_cluster.pois))
            first_report = first_poi.report
            good_pois = []
            for poi in poi_cluster.pois:
                if poi.function is None:
                    _l.warning(f"POI %s does not have a function. Dropping it!", poi)
                    continue

                if poi.function.file_path is None:
                    _l.warning(f"POI %s does not have a file. Dropping it!", poi)
                    continue

                # blacklisted functions
                if any(func in poi.function.name for func in blacklist_funcs):
                    _l.warning(f"POI %s is an LLVMFuzzerTestOneInput function. Dropping it!", poi)
                    continue

                # blacklisted paths
                rel_path = poi.function.file_path.relative_to(self._program.source_root) if str(
                    poi.function.file_path).startswith(str(self._program.source_root)) else poi.function.file_path
                if rel_path.parts and rel_path.parts[0] in blacklist_paths:
                    _l.warning(
                        f"POI %s has a blacklisted first directory in its path: {rel_path.parts[0]}. Dropping it!", poi)
                    continue
                # if any(part in poi.function.file_path.parts for part in blacklist_paths):
                #     _l.warning(f"POI %s has a blacklisted part in its path. Dropping it!", poi)
                #     continue

                # # function with no source code
                # if not self._program.code.functions_by_name(poi.function.name):
                #     _l.critical("Function %s not found in the code. Dropping POI %s. Maybe indexer fail?", poi.function, poi)
                #     continue

                if not poi.report:
                    poi.report = first_report

                good_pois.append(poi)

            if good_pois:
                filtered_clusters.append(PoICluster.from_pois(good_pois, source=poi_cluster.source))

        return filtered_clusters

    def _cluster_pois_round_1(self, pois: list[PoI]) -> list[PoICluster]:
        clusters = []

        # In projects that contain the crashing commit we can cluster the PoIs by the functions
        # that are in the commit and some other analysis (if space allows). We do this because it is likely that the
        # patch target is a function changed and contained in some other analysis (like call trace), but many
        # may be required to patch the bug
        diff_and_more_pois = []
        for poi in pois:
            if PoISource.DIFFGUY in poi.sources and len(poi.sources) > 1:
                # keep it from inflating the poi_clusters
                if PoISource.COMMIT in poi.sources:
                    _l.debug("Removing commit source from PoI %s", poi)
                    poi.sources.remove(PoISource.COMMIT)
                    diff_and_more_pois.append(poi)
                    continue
            if PoISource.COMMIT in poi.sources and len(poi.sources) > 1:
                diff_and_more_pois.append(poi)

        if diff_and_more_pois:
            _l.debug("Creating a new cluster for commit diff PoIs: %s", diff_and_more_pois)
            if len(diff_and_more_pois) > self._max_cluster_size:
                _l.warning("Too many PoIs (%d) in commit-cluster. Reducing the size to %d", len(diff_and_more_pois), self._max_cluster_size)
                # first reorder the list by commit_and_report overlap
                diff_and_more_pois = sorted(diff_and_more_pois, key=lambda x: len(x.sources), reverse=True)
                diff_and_more_pois = diff_and_more_pois[:self._max_cluster_size]
            clusters.append(PoICluster.from_pois(diff_and_more_pois, source=PoISource.MERGE))

        # for any singletons that remain, we should make the back into clusters
        # Only create singleton clusters for POIs not already in diff_and_more_pois
        for poi in diff_and_more_pois:
            clusters.append(PoICluster.from_pois([poi.copy()], source=PoISource.MERGE))
        remaining_pois = [poi for poi in pois if poi not in diff_and_more_pois]
        for poi in remaining_pois:
            clusters.append(PoICluster.from_pois([poi], source=PoISource.MERGE))

        return clusters

    def _reduce_stack_trace_pois(self, pois: list[PoI]) -> list[PoI]:
        """
        Reduce the number of stack trace PoIs to a maximum number.
        """
        new_pois = []
        stack_pois_num = 0
        for poi in pois:
            if PoISource.STACK_TRACE in poi.sources:
                stack_pois_num += 1
                if stack_pois_num > self._max_stack_trace:
                    continue
            new_pois.append(poi)
        return new_pois

    def _order_clusters(self, poi_clusters: list[PoICluster]) -> list[PoICluster]:
        """
        Order the POIs based on their importance. Here is the current algorithm of most important PoIs:
        1. Clusters containing PoIs specified by the user are automatically the most important
        2. The sum of the number of sources of all PoIs in the cluster are more important
        3. To tie-break, use the averaged score of the sources
        """
        # first, sort by user-specified PoIs
        user_poi_cluster = []
        other_poi_cluster = []

        for cluster in poi_clusters:
            for poi in cluster.pois:
                if PoISource.USER in poi.sources:
                    user_poi_cluster.append(cluster)
                    break
            else:
                other_poi_cluster.append(cluster)
        poi_clusters = user_poi_cluster + other_poi_cluster

        cluster_and_sources = []
        for cluster in poi_clusters:
            source_count = sum(len(poi.sources) for poi in cluster.pois)
            source_strength_avg = sum(sum(list(poi.sources)) for poi in cluster.pois) / source_count
            cluster_and_sources.append(
                (
                    cluster,
                    sum(len(poi.sources) for poi in cluster.pois),
                    source_strength_avg
                )
            )
        # finally, sort by the number of sources (bigger better) and source strength (smaller better)
        poi_clusters = [c[0] for c in sorted(cluster_and_sources, key=lambda x: (x[1], -x[2]), reverse=True)]

        return poi_clusters
