import logging
import os
import time
from pathlib import Path
from typing import Optional
from shellphish_crs_utils.models.crs_reports import POIReport
import hashlib
from concurrent.futures import ProcessPoolExecutor, as_completed, TimeoutError as FutureTimeoutError

from kumushi.analyses import Analysis, DEFAULT_ANALYSES, AnalysisWeight, StackTraceAnalysis, AnalysisTimeoutError
from kumushi.data import PoICluster
from kumushi.aixcc import AICCProgram
from kumushi.static_tools.static_analysis import StaticAnalyzer
from kumushi.util import TMP_POI_DIR, save_clusters_to_yaml, save_clusters_to_file, load_clusters_from_file
from .analyses import WEIGHTLESS_ANALYSES
from .rca_mode import RCAMode

from .analyses import CallTraceAnalysis, VariableDependenciesAnalysis

from kumushi.poi_cluster_ranker import PoIClusterRanker

_DEBUG = os.getenv("DEBUG", "False") != "False"
_l = (logging.getLogger(__name__))

class RootCauseAnalyzer:
    def __init__(
        self,
        program: AICCProgram,
        # analyses tweaks:
        rca_mode: int = RCAMode.HYBRID,
        timeout: int = 30 * 60,  # 30 minutes
        max_cores: int = 4,
        used_weightless_pois: int = 3,
        # dynamic analysis
        coverage_target_dir: Path | None = None,
        coverage_target_metadata_path: Path | None = None,
        # external analyses
        benzene_results_path: Path | None = None,
        # output folder
        output_folder: Path | None = None,
        **kwargs
    ):
        self.program = program
        self.timeout = timeout
        self.benzene_results_path = benzene_results_path

        self._rca_mode = rca_mode
        self._max_cores = max_cores if not _DEBUG else 1
        if _DEBUG:
            _l.info("Using debug mode, will be using one core for all analyses!")

        # AIxCC args
        self.poi_report = self.program.poi_report
        self.project_id = self.poi_report.project_id
        self.project_name = self.poi_report.project_name
        self.delta_mode = self.program.delta_mode

        # TODO: put this back later, initing does heavy work that should be done later
        # coverage analysis
        # self.coverage_collector = SmartCallTracer(
        #    self.crashing_program.crashing_input, "aixcc", coverage_target_dir,
        #    coverage_target_metadata_path
        # )
        self.static_analyzer = None
        # running analyses and scheduling
        self._completed_analyses = []
        self.output_folder: Path = output_folder

        # immediately start analyses that complete in less than 10ish seconds
        self._all_weightless_pois = self._run_weightless_analysis()
        self.crashing_location_poi = self._find_crashing_location_poi()
        # publicly used weightless pois should be a subset of all weightless pois
        self.weightless_pois = self._all_weightless_pois[:used_weightless_pois]

        self.pois = None

    @staticmethod
    def generate_rca_hash(poi_clusters: list[PoICluster]) -> str:
        pre_str = ""
        for cluster in poi_clusters:
            for poi in cluster.pois:
                if poi.function is None:
                    continue
                pre_str += str(poi.function.name)

        hasher = hashlib.md5()
        hasher.update(pre_str.encode())
        return hasher.hexdigest()

    def _run_weightless_analysis(self) -> list[PoICluster]:
        for analysis_cls in WEIGHTLESS_ANALYSES:
            analysis = self._init_analysis(analysis_cls)
            # catch potential timeouts and exceptions
            try:
                analysis.analyze()
            except Exception as e:
                _l.error(f"Weightless analysis {analysis.__class__.__name__} failed: {e}")
                continue

            self._completed_analyses.append(analysis)
        return PoIClusterRanker(self._completed_analyses, self.program, mode=RCAMode.WEIGHTLESS).rank_poi_clusters()

    def _init_analysis(self, analysis_cls: type[Analysis]) -> Analysis:
        extra_kwargs = {}
        if analysis_cls is VariableDependenciesAnalysis:
            extra_kwargs["static_analyzer"] = self.static_analyzer
        elif analysis_cls is CallTraceAnalysis:
            extra_kwargs["crashing_location_poi"] = self.crashing_location_poi

        program = self.program if not analysis_cls.REQUIRES_NEW_PROGRAM else self.program.copy()
        analysis = analysis_cls(program, **extra_kwargs)
        return analysis

    def _find_crashing_location_poi(self):
        st_analysis: StackTraceAnalysis = [a for a in self._completed_analyses if a.NAME == StackTraceAnalysis.NAME][0]
        if len(st_analysis.poi_clusters) == 0:
            return None
        crashing_poi = st_analysis.poi_clusters[0].pois[0]
        return crashing_poi

    def _finalize_analysis(self) -> list[PoICluster]:
        """Single function to finalize all analyses and generate final results"""
        self.program.code.reinit_or_get_function_resolver()
        ranker = PoIClusterRanker(self._completed_analyses, self.program, mode=self._rca_mode)
        self.pois = ranker.rank_poi_clusters()
        if len(self.pois) >= 11:
            _l.info(f"Reduce from {len(self.pois)} to top 11 pois")
            self.pois = self.pois[:11]
        _l.info(f"The following pois were found: %s", self.pois)
        if self.output_folder:
            save_clusters_to_yaml(self.pois, self.output_folder, self.generate_rca_hash(self.pois), self.program)
            _l.info(f"PoIs saved to %s", self.output_folder)
        return self.pois

    def analyze(self) -> list[PoICluster]:
        # static analysis init
        self.static_analyzer = StaticAnalyzer(
            self.crashing_location_poi,
            self.project_id,
            self.project_name
        )
        
        if self._max_cores == 1:
            self._single_thread_analyze()
        else:
            try:
                self._multi_process_analyze()
            except TimeoutError:
                _l.error("Analysis timed out, stopping further analyses...")

        return self._finalize_analysis()

    def _analysis_should_run(self, analysis_cls: type[Analysis]) -> bool:
        should_run = (
            self._rca_mode == RCAMode.HYBRID or
            (self._rca_mode == RCAMode.LIGHT and analysis_cls.ANALYSIS_WEIGHT == AnalysisWeight.LIGHT) or
            (self._rca_mode == RCAMode.HEAVY and analysis_cls.ANALYSIS_WEIGHT == AnalysisWeight.HEAVY)
        )
        return should_run

    def _single_thread_analyze(self):
        """
        Very simple ordered single-thread analysis that will go in the order the analyses were
        specified
        """
        for analysis_cls, enabled in DEFAULT_ANALYSES:
            if not enabled:
                continue

            if self._analysis_should_run(analysis_cls):
                analysis = self._init_analysis(analysis_cls)
                analysis.analyze()
                self._completed_analyses.append(analysis)

    def _multi_process_analyze(self):
        """
        Simplified multiprocessing analysis that runs all analyses in parallel
        with individual timeouts and collects results
        """
        # Get enabled analyses
        analyses = []
        for analysis_cls, enabled in DEFAULT_ANALYSES:
            if not enabled:
                _l.info("Skipping analysis %s since it is disabled.", analysis_cls.__name__)
                continue

            if self._analysis_should_run(analysis_cls):
                analyses.append(self._init_analysis(analysis_cls))

        if not analyses:
            _l.info("No analyses to run")
            return

        _l.info("Enabled analyses: %s", [analysis.__class__.__name__ for analysis in analyses])
        _l.info("Scheduling %s analyses on %d cores", len(analyses), self._max_cores)

        # Reset function resolver for multiprocessing
        try:
            self.program.reset_function_resolver()
        except Exception as e:
            _l.exception("Failed to reset function resolver: %s", e)
        executor_shutdown = True

        # Run analyses with ProcessPoolExecutor for better timeout handling
        with ProcessPoolExecutor(max_workers=self._max_cores) as executor:
            # Submit all analyses
            future_to_analysis = {}
            for analysis in analyses:
                future = executor.submit(self._analysis_worker, analysis)
                future_to_analysis[future] = analysis

            # Collect results with timeout
            start_time = time.time()
            completed_count = 0

            try:
                # Normal collection with timeout
                for future in as_completed(future_to_analysis, timeout=self.timeout):
                    analysis = future_to_analysis[future]
                    try:
                        result = future.result(timeout=1)
                        if result:
                            self._completed_analyses.append(result)
                            _l.info(f"Analysis {analysis.__class__.__name__} completed successfully")
                        completed_count += 1
                    except FutureTimeoutError:
                        _l.error(f"Analysis {analysis.__class__.__name__} timed out while collecting result")
                    except Exception as e:
                        _l.error(f"Analysis {analysis.__class__.__name__} failed: {e}")

            except FutureTimeoutError:
                # Immediate shutdown on timeout
                _l.warning(
                    f"Analysis timeout reached. {completed_count} of {len(future_to_analysis)} analyses completed.")

                # Try to cancel unfinished futures
                cancelled_count = 0
                still_running_count = 0

                for future in future_to_analysis:
                    if not future.done():
                        if future.cancel():
                            cancelled_count += 1
                        else:
                            still_running_count += 1

                _l.info(f"Cancellation: {cancelled_count} cancelled, {still_running_count} still running")

                # Immediate shutdown - don't wait for running processes
                executor.shutdown(wait=False)
                executor_shutdown = False
                _l.warning(
                    f"Executor shutdown immediately. {still_running_count} processes may continue in background.")

                _l.info(f"Final count: {completed_count} of {len(future_to_analysis)} analyses completed")
                return

            finally:
                # Only shutdown if we haven't already done immediate shutdown
                if executor_shutdown:
                    _l.info("Normal completion - shutting down executor gracefully")
                    executor.shutdown(wait=True)

            _l.info(f"All analyses completed successfully: {completed_count} of {len(future_to_analysis)}")

            _l.info(f"Completed {completed_count}/{len(analyses)} analyses")

    @staticmethod
    def _analysis_worker(analysis: Analysis) -> Optional[Analysis]:
        """
        Worker function that runs a single analysis with timeout
        """
        _l.info(f"Analysis {analysis.__class__.__name__} starting...")
        
        try:
            # Run the analysis with timeout
            analysis.analyze()
            
            # Save results to disk if not in debug mode
            if analysis.poi_clusters and os.getenv("DEBUG", None) is None:
                clusters_file = TMP_POI_DIR / f"{analysis.__class__.__name__}"
                save_clusters_to_file(analysis.poi_clusters, clusters_file)
                _l.info(f"Analysis {analysis.__class__.__name__} results saved to {clusters_file}")
            
            return analysis
            
        except Exception as e:
            import traceback
            _l.error(f"Analysis {analysis.__class__.__name__} failed with exception: {e}")
            _l.error(f"Traceback: {traceback.format_exc()}")
            return None

    @staticmethod
    def kumushi_report_to_clusters(report_path: Path):
        import yaml
        with open(report_path, "r") as f:
            report = POIReport(**yaml.safe_load(f))
        return report.poi_clusters