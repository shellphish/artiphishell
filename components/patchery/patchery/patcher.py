import logging
import math
import os
import time
import traceback
import typing
import concurrent.futures
import threading
from pathlib import Path

from kumushi.data import Program, PoICluster
from .logger import MultiHandler
from .generator import LLMPatchGenerator, LLMPromptingStyles, LLMPlanPatchGenerator, LLMTools
from .generator.prompts.patch_summary import PATCH_SUMMARY_PROMPT
from .utils import MULTITHREAD_LOG_FOLDER_BASE, get_new_logging_dir
from .verifier import PatchVerifier
from .verifier.patch_verifier import AlertEliminationVerificationPass
from .data.patch import Patch

_l = logging.getLogger(__name__)
_DEBUG = bool(os.getenv("DEBUG", False))

if typing.TYPE_CHECKING:
    from kumushi.aixcc import AICCProgram

first_patch_found = threading.Event()  # Flag to signal first patch found

class PatchGenerationResult(typing.TypedDict):
    patches: list[Patch]
    poi_cluster_index: int
    cost: float
    model: str
    count: int

class Patcher:
    def __init__(
        self,
        program_info: Program,
        model: str,
        max_patches=1,
        max_attempts=10,
        max_pois=10,
        max_poi_gen_continues=6,
        max_func_size=900,
        restore_src=True,
        patch_planning=False,
        use_report_analyzer=False,
        # TODO: deprecate the flags below
        prompting_style: LLMPromptingStyles | None = None,
        crashing_commit=None,
        indices_by_commit=None,
        changed_func_by_commits=None,
        func_indices: Path | None = None,
        func_json_dir=None,
        threaded=True,
        threads=5,
        **kwargs
    ):
        self.program_info: Program = program_info
        self.program_info.setup_program()
        self.threaded = threaded
        if _DEBUG:
            _l.info("Running in DEBUG mode. Threaded patching is disabled.")
            self.threaded = False

        self.threads = threads

        self.model = model
        self.max_patches = max_patches
        self.max_attempts = max_attempts
        self.max_pois = max_pois
        self.max_func_size = max_func_size
        self.smart_mode = False

        self.use_report_analyzer = use_report_analyzer
        self.prompting_style = prompting_style
        self.restore_src = restore_src
        self.crashing_commit = crashing_commit
        self._patch_planning = patch_planning

        self.indices_by_commit = indices_by_commit
        self.changed_func_by_commits = changed_func_by_commits
        self.func_indices = func_indices
        self.func_json_dir = func_json_dir
        self.max_poi_gen_continues = max_poi_gen_continues

        # reporting metrics
        self._start_time: int = 0
        self._end_time: int = 0
        self.seen_pois = 0
        self.completed_poi_rounds = 0
        self.total_cost = 0.0
        self.total_time: int = 0

        self.should_work = True

    def _round_heat(self, current_round: int):
        """
        Calculate the temperature for the patch generation based on the current round.
        """
        temperature = 0.0
        if current_round < self.max_attempts / 2:
            temperature = 0.0
        if current_round > math.floor(self.max_attempts / 2):
            temperature = 0.1
        return temperature

    def _heat_sum(self, current_round: int, failure_penalty: float):
        temperature = 0.0
        temperature += self._round_heat(current_round)
        temperature += failure_penalty

        if temperature >= 1.0:
            temperature = 0.99
        if temperature < 0.0:
            temperature = 0.0
        return temperature

    def _gen_and_verify_core(
        self,
        poi_cluster: PoICluster = None,
        index: int = 0,
        reports: list | None = None,
        patch_generator: LLMPatchGenerator = None,
        thread_id: int | None = None,
        program_info: Program = None,
        **kwargs,
    ):
        failed_patch = None
        total_runs = 0
        src_just_restored = False
        patches = []
        cost = 0.0
        patch_verifier = PatchVerifier(program_info, smart_mode=self.smart_mode, patcher=self)
        patch_verifier.failure_heat = 0.0
        patch_generator.temperature = 0.0
        patch_generator.total_continues = 0

        _l.debug(f"Run settings: total_runs={total_runs}, max_attempts={self.max_attempts}")
        while (len(patches) < self.max_patches) and total_runs < self.max_attempts:
            if total_runs > 0:
                self.completed_poi_rounds += 1

            # if we are in a threading context, we need to check if the thread is still running and valid
            if thread_id is not None:
                if not self.should_work:
                    _l.warning(f"All threads have been stopped. Stopping {thread_id}!")
                    return patches, cost

            if patch_generator.total_continues > self.max_poi_gen_continues:
                _l.warning(
                    "Attempted to patch with a context too large, which required continues, too many times. Skipping this PoI!")
                break

            total_runs += 1
            # calculate the temperature for the patch generation
            temperature = 0.0
            temperature += self._heat_sum(total_runs, patch_verifier.failure_heat)
            if temperature >= 0.5:
                temperature = 0.5
            patch_generator.temperature = temperature
            _l.debug(f"🌡️  Setting Temperature: {temperature}")
            _l.info(
                f"🤖 Starting run {total_runs}/{self.max_attempts} for {poi_cluster} {index}/{self.max_pois} ...")
            _l.info(f"🤖 Generating patch {len(patches) + 1}/{self.max_patches}...")
            reports = reports or [poi_cluster.pois[0].report]
            # if self.program_info.apply_refine_patch() is not None:
            #     _l.info("✅Refine Patch Applied Successfully")
            # else:
            #     _l.info("❌Refine Patch failled to apply")
            patch = patch_generator.generate_patch(
                poi_cluster, reports, failed_patch=failed_patch, **kwargs
            )
            cost += patch_generator.cost

            if patch is None:
                _l.error("🚫 Patch generation failed.")
                continue

            verified, reasoning = patch_verifier.verify(patch)
            cost += patch_verifier.cost

            if verified:
                patch_summary, summary_cost = self.generate_patch_summary(patch.diff, patch_generator.prompt_history)
                cost += summary_cost
                if hasattr(patch, "metadata"):
                    patch.metadata["summary"] = patch_summary
                patches.append(patch)
                if not first_patch_found.is_set():
                    first_patch_found.set()
                    self.should_work = False
                break
            else:
                failed_patch = patch
                failed_patch.reasoning = reasoning

        if total_runs >= self.max_attempts:
            _l.critical(f"Max runs reached. Could not generate {self.max_patches} patch(es).")

        return patches, cost

    @staticmethod
    def _log_if_failed(fut):
        try:
            # this will re‑raise any exception from the worker
            fut.result()
        except concurrent.futures.CancelledError:
            # logs the cancellation
            _l.warning("Worker thread was cancelled.")
        except Exception:
            # logs the full traceback
            _l.error("Worker thread raised exception:\n%s", traceback.format_exc())

    def _reduce_pois(self, poi_clusters: list[PoICluster]):
        """
        Reduce the number of PoIs in the clusters to the maximum allowed.
        This is a helper function to ensure we don't exceed the max_pois limit.
        """
        if len(poi_clusters) > self.max_pois:
            _l.warning(
                "The max allowed pois are %d, but we have %d pois. Truncating the pois...",
                self.max_pois,
                len(poi_clusters),
            )
            poi_clusters = poi_clusters[:self.max_pois]
        return poi_clusters

    def _generate_reports(self, poi_clusters: list[PoICluster], **kwargs):
        """
        Generate reports for the given PoI clusters.
        This is a helper function to create reports for the PoIs.
        """
        if hasattr(self.program_info, "poi_report"):
            report = self.program_info.poi_report.additional_information.get("asan_report_data", {}).get(
                "cleaned_report", None)
            if report:
                return [report]
        return None



    def _generate_verified_patches_single_thread(self, poi_clusters: list[PoICluster], reports=None, **kwargs):
        generator_cls = LLMPlanPatchGenerator if self._patch_planning else LLMPatchGenerator
        patch_generator = generator_cls(
            self.program_info, prompt_style=self.prompting_style, model=self.model, use_failed_patch_reasoning=True,
            use_failed_patch_code=True
        )
        out_patches = []
        for index, poi_cluster in enumerate(poi_clusters):
            _l.info(
                f"we have {len(poi_clusters)} pois. Per poi we attempt {self.max_attempts} attempts. In total we try {len(poi_clusters) * self.max_attempts} times."
            )

            patches, generator_cost = self._gen_and_verify_core(
                poi_cluster=poi_cluster,
                index=index,
                reports=reports,
                patch_generator=patch_generator,
                program_info=self.program_info,
                **kwargs,
            )
            _l.info(f"💰cost for this poi cluster is {generator_cost}")
            self.total_cost += generator_cost
            self.total_cost = round(self.total_cost, 5)
            _l.info(f"💰total cost we spent until now {self.total_cost}")
            if patches:
                out_patches.append({
                    "patches": patches,
                    "poi_cluster_index": index,
                    "cost": self.total_cost,
                    "model": self.model,
                    "count": len(patches)
                })
                _l.info(f"🎉 {len(patches)} patch(es) generated and verified.")
                break

        return out_patches

    def generate_verified_patches(self, poi_clusters: list[PoICluster], **kwargs) -> typing.List[PatchGenerationResult]:
        self._start_time = time.time()
        poi_clusters = self._reduce_pois(poi_clusters)
        _l.info(f"%d PoIs (clusters) will be used for patch generation...", len(poi_clusters))
        _l.info("We have %d PoIs. Per poi we attempt %d attempts. In total we try %d max times to patch.", len(poi_clusters), self.max_attempts, len(poi_clusters) * self.max_attempts)
        _l.info("The following PoIs will be used for patching: %s", poi_clusters)
        reports = self._generate_reports(poi_clusters, **kwargs)
        self.program_info.check_and_set_build_checker_works()
        if self.threaded:
            _l.info("Using multi-threaded patch generation on %d threads.", self.threads)
            all_patches = self._generate_verified_patches_multi_thread(poi_clusters, reports=reports, **kwargs)
        else:
            _l.info("Using single-threaded patch generation.")
            all_patches = self._generate_verified_patches_single_thread(poi_clusters, reports=reports, **kwargs)

        self._end_time = time.time()
        self.total_time = self._end_time - self._start_time
        str_time_taken = time.strftime("%M:%S", time.gmtime(self.total_time))
        _l.info("We saw a total of %d PoIs and completed %d rounds of patch generation. It took %s minutes long.", self.seen_pois, self.completed_poi_rounds, str_time_taken)
        return all_patches

    #
    # Multi-thread patch generation & Helper functions
    #

    def _generate_verified_patches_multi_thread(self, poi_clusters: list[PoICluster], reports=None, **kwargs):
        # Collection to store all generated patches
        all_patches = []
        logging_dir = get_new_logging_dir()
        _l.info("Multithreaded logging directory: %s", logging_dir)
        multi_handler = MultiHandler(logging_dir)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        multi_handler.setFormatter(formatter)
        root_logger = logging.getLogger()
        root_logger.addHandler(multi_handler)

        running_futures = set()
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            # Submit all clusters as before
            for index, poi_cluster in enumerate(poi_clusters):
                if first_patch_found.is_set():
                    _l.info(f"Skipping poi_cluster {index} as a patch was already found")
                    continue

                thread_id = index % self.threads
                _l.info(f"Starting poi_cluster {index} on thread {thread_id}")

                fut = executor.submit(
                    self._threaded_process_poi,
                    poi_cluster,
                    index,
                    reports,
                    self.model,
                    thread_id=thread_id,
                    **kwargs
                )
                fut.add_done_callback(self._log_if_failed)
                running_futures.add(fut)
                _l.info(f"Submitted poi_cluster {index}; total running: {len(running_futures)}")

            # Wait loop: stop as soon as first_patch_found OR no pending futures left
            _l.info("Waiting for first patch or completion of all tasks...")
            pending = set(running_futures)
            while pending and not first_patch_found.is_set():
                done, pending = concurrent.futures.wait(
                    pending,
                    timeout=5,
                    return_when=concurrent.futures.FIRST_COMPLETED
                )
                # Process each newly done future
                for fut in done:
                    all_patches = self._process_future_result(fut, 0, all_patches)

            # Decide why we broke out
            if first_patch_found.is_set():
                _l.info("First patch found; cancelling remaining tasks...")
            else:
                _l.info("All tasks completed without finding a patch; continuing...")

            # Signal threads to stop, cancel pending futures
            self.should_work = False
            for fut in pending:
                fut.cancel()

            # Finally, process any non-cancelled futures left
            for fut in pending:
                if not fut.cancelled():
                    # each process gets a remaining 30 seconds to finish
                    all_patches = self._process_future_result(fut, 0, all_patches, timeout=30)

        # Log the total number of patches found
        total_patch_count = sum(item["count"] for item in all_patches)
        _l.info(f"Total of {total_patch_count} patches generated across all clusters and models")

        for log_path in Path(logging_dir).iterdir():
            _l.info(f'🧵Show log for thread {log_path.stem}')
            with open(log_path, errors='ignore') as log_file:
                _l.info(log_file.read())
            _l.info(f"🧥Finish showing log for thread {log_path.stem}")

        # Return all collected patches
        if all_patches:
            _l.info(f"🎉 {len(all_patches)} patch(es) generated and verified.")
        return all_patches

    def _process_future_result(self, future, report_cost: float, all_patches: list, timeout=None) -> list :
        """
        Process the result of a future and update the total cost.
        This function is called when a future is completed.
        It retrieves the patches and cost from the future and updates the total cost.
        If patches were found, they are added to the all_patches list.
        :param future: The future object representing the asynchronous task.
        :param report_cost: The cost of the report generation.
        :param all_patches: The list to store all generated patches.
        :return: The updated all_patches list.
        """
        try:
            patches, generator_cost, index, model_name = future.result(timeout=timeout)
            _l.info(f"cost for this poi cluster {index} with model {model_name} is {generator_cost}")
            # Safely update the total cost
            self.total_cost += report_cost + generator_cost
            self.total_cost = round(self.total_cost, ndigits=5)
            _l.info(f"💰total cost we spent until now {self.total_cost}")
            # If patches were found, add them to our collection
            if patches:
                # Store patches along with metadata
                all_patches.append({
                    "patches": patches,
                    "poi_cluster_index": index,
                    "cost": generator_cost,
                    "model": model_name,
                    "count": len(patches)
                })
                _l.info(
                    f"🎉 {len(patches)} patch(es) generated and verified with model {model_name} for poi_cluster {index}.")
            return all_patches
        except Exception as e:
            _l.error(f"Error processing poi_cluster: {e}")
            return all_patches

    def _threaded_process_poi(self, poi_cluster, index, reports, model_name, thread_id=None, **kwargs):
        """Process a single poi_cluster with the specified model."""
        generator_cls = LLMPlanPatchGenerator if self._patch_planning else LLMPatchGenerator

        # must make a copy of the project
        program_info = self.program_info.copy(pre_built=True)
        patch_generator = generator_cls(
            program_info, prompt_style=self.prompting_style, model=model_name, use_failed_patch_reasoning=True,
            use_failed_patch_code=True
        )
        _corrected_poi_cluster = PoICluster.rewrite_absolute_path(poi_cluster, self.program_info.source_root, program_info.source_root)
        _l.info(f"Processing poi_cluster {index} with model {model_name} on thread {thread_id}")
        self.seen_pois += 1
        try:
            patches, generator_cost = self._gen_and_verify_core(
                poi_cluster=_corrected_poi_cluster,
                index=index,
                reports=reports,
                patch_generator=patch_generator,
                thread_id=thread_id,
                program_info=program_info,
                **kwargs,
            )
        except Exception as e:
            _l.error(f"Error processing poi_cluster {index} with model {model_name}: {e}")
            patches = []
            generator_cost = 0.0

        program_info.cleanup()
        _l.info(f"💰cost for this poi cluster {index} with model {model_name} is {generator_cost}")
        return patches, generator_cost, index, model_name

    def generate_patch_summary(self, patch_diff: str, prompt_history: list[str]) -> tuple[str, float]:
        """
        Generate a summary of the patch using the LLM.
        :param patch_diff: The diff of the patch to summarize.
        :param prompt_history: The history of prompts used in the patch generation.
        :return: A tuple containing the patch summary and the cost of the LLM call.
        """
        patch_summary, cost = LLMTools(PATCH_SUMMARY_PROMPT,
                                       {"PATCH_DIFF": patch_diff, "LLM_HISTORY": "\n".join(prompt_history)},
                                       self.model).call_llm()
        return patch_summary, cost
