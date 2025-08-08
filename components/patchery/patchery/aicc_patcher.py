import logging
import json
import os
import hashlib
from pathlib import Path
from typing import Optional, List

import yaml

from shellphish_crs_utils.models.crs_reports import RepresentativeFullPoVReport, POIReport
from shellphish_crs_utils.models.patch import PatchMetaData
from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject
from analysis_graph.models.crashes import GeneratedPatch
from crs_telemetry.utils import get_otel_tracer, status_ok, get_current_span, status_error

import patchery
from patchery import Patcher, LLMPatchGenerator
from patchery.utils import absolute_path_finder, read_src_from_file, find_src_root_from_commit, llm_model_name

from kumushi.root_cause_analyzer import RootCauseAnalyzer
from kumushi.rca_mode import RCAMode
from kumushi.aixcc import AICCProgram
from kumushi.data import ProgramInput, ProgramInputType, PoI, PoICluster, PoISource, Program
from kumushi.util import load_clusters_from_yaml

tracer = get_otel_tracer()

_l = logging.getLogger(__name__)


class AICCPatcher(Patcher):
    DEFAULT_LLM_MODEL = 'claude-3.7-sonnet'

    def __init__(
        self,
        program: AICCProgram,
        # TODO: update raw report to literally be the raw data
        patch_output_dir=None,
        patch_metadata_output_dir=None,
        local_run: bool = False,
        kumushi_clusters: list | None = None,
        **kwargs
    ):

        # private api
        self._patch_output_dir = patch_output_dir
        self._patch_metadata_output_dir = patch_metadata_output_dir
        self._kumushi_clusters = kumushi_clusters
        self._weightless_limited_attempts = 2

        # public api
        self.is_local_run = local_run
        self.pois = []

        super().__init__(program, llm_model_name(model=self.DEFAULT_LLM_MODEL), **kwargs)

        # generate pois for patching
        self.pois = self.poi_clusters_from_kumushi()
        _l.info(f"{len(self.pois)} PoIs provided for patching attempts")

    #
    # init helpers
    #

    @tracer.start_as_current_span("kumushi_clustering")
    def poi_clusters_from_kumushi(self, kumushi_report=None):
        if not self._kumushi_clusters:
            _l.info("No KumuShi report provided, generating PoIs from local KumuShi run...")
            rca = RootCauseAnalyzer(
                self.program_info,
                rca_mode=RCAMode.WEIGHTLESS
            )
            poi_clusters = rca.weightless_pois
            _l.info(f"Since we are using KumuShi in weightless, we will limit attempts to only %d.", self._weightless_limited_attempts)
            self.max_attempts = self._weightless_limited_attempts
            self.program_info.code.reinit_or_get_function_resolver()
        else:
            # we have loaded some from a kumushi report passed in
            self.smart_mode = True
            poi_clusters = self._kumushi_clusters

        return self.program_info.update_pois_for_src_path(poi_clusters)

    def _update_patch_output_locations(self) -> tuple[Path, Path]:
        # patch output location
        patch_name = hashlib.md5(os.urandom(16)).hexdigest()
        patch_output_dir = Path(self._patch_output_dir) if self._patch_output_dir else None
        patch_metadata_output_dir = Path(self._patch_metadata_output_dir) if self._patch_metadata_output_dir else None
        assert patch_output_dir.exists()
        assert patch_metadata_output_dir.exists()
        return patch_output_dir / patch_name, patch_metadata_output_dir / patch_name

    @tracer.start_as_current_span("patchery.gen_and_verify_core")
    def _gen_and_verify_core(self, *args, **kwargs):
        return super()._gen_and_verify_core(*args, **kwargs)

    @tracer.start_as_current_span("generate_verified_patches")
    def generate_verified_patches(self, *args, **kwargs):
        patcher_name = "PatcherY" if not self.smart_mode else "PatcherY_Smart"
        span = get_current_span()
        verified_patches = super().generate_verified_patches(self.pois, **kwargs)
        if verified_patches:
            for patch_group in verified_patches:
                for patch in patch_group['patches']:
                    patch_diff = self.program_info.git_diff(patch)
                    patch_output_file, patch_metadata_output_file = self._update_patch_output_locations()
                    build_request = patch.metadata.get('build_request_id', None)
                    summary = patch.metadata.get('summary', None)
                    if build_request is None:
                        _l.critical("No build request ID found in patch metadata, using crash report ID instead.")

                    # write patch diff
                    for i in range(5):
                        try:
                            GeneratedPatch.upload_patch(
                                self.program_info.poi_report.project_id,
                                patch_output_file.name,
                                patch_diff, self.program_info.poi_report.crash_report_id,
                                [self.program_info.poi_report.crash_report_id],
                                [],
                                None,
                                patcher_name=patcher_name,
                                total_cost=patch_group['cost'],
                                build_request_id=build_request,
                                summary=summary,
                            )
                        except Exception as e:
                            _l.error("Failed to upload patch: %s", e)
                            import time
                            time.sleep(30)
                    with open(patch_metadata_output_file, "w") as f:
                        patch_metadata: PatchMetaData = PatchMetaData(
                            patcher_name=patcher_name,
                            total_cost=patch_group['cost'],
                            poi_report_id=self.program_info.poi_report.crash_report_id,
                            pdt_project_id=self.program_info.poi_report.project_id,
                            pdt_project_name=self.program_info.poi_report.project_name,
                            pdt_harness_info_id=self.program_info.poi_report.harness_info_id,
                            build_request_id=build_request,
                        )
                        yaml.safe_dump(patch_metadata.model_dump(), f, default_flow_style=False, sort_keys=False)
                    with open(patch_output_file, "w") as f:
                        f.write(patch_diff)

                    _l.info(f'Patch data saved! Patch: %s | Metadata: %s', patch_output_file, patch_metadata_output_file)
                    span.add_event("generated_patch", {"patch": patch_diff})
                    span.set_status(status_ok())
            _l.info(f"💸 The total cost of this patch was {self.total_cost} dollars.")
            span.set_attributes({"gen_ai.request.model": self.model,
                                 "gen_ai.usage.cost": self.total_cost, })
        else:
            _l.info(f"💸 We could not make a patch. The total cost was {self.total_cost} dollars.")
            _l.error("Failed to generate any verified patches.")
            span.set_status(status_error(), "No patch generated.")
        return verified_patches

    @classmethod
    @tracer.start_as_current_span("patchery.from_files")
    def from_files(
            cls,
            *args,
            target_root: Path = None,
            source_root: Path = None,
            report_yaml_path: Path = None,
            project_metadata_path=None,
            raw_report_path=None,
            function_json_dir=None,
            function_indices=None,
            alerting_inputs_path=None,
            patch_output_dir=None,
            patch_metadata_output_dir=None,
            crashing_commit=None,
            indices_by_commit=None,
            changed_func_by_commit=None,
            patch_planning=None,
            local_run=False,
            kumushi_report_path=None,
            delta_mode=False,
            coverage_build_project_path: Path=None,
            patch_request_meta: Path = None,
            bypassing_inputs: str = None,
            **kwargs
    ) -> "AICCPatcher":

        # validate outputs locations exists
        if patch_output_dir is not None:
            Path(patch_output_dir).mkdir(exist_ok=True)
        if patch_metadata_output_dir is not None:
            Path(patch_metadata_output_dir).mkdir(exist_ok=True)
        if not bypassing_inputs:
            bypassing_inputs_path = None
        else:
            bypassing_inputs_path = Path(bypassing_inputs)

        # inputs path
        if isinstance(alerting_inputs_path, (str, Path)):
            # TODO: update code names, apparently this is a path to a file, not a list
            alerting_inputs_path = [Path(alerting_inputs_path)]
        elif isinstance(alerting_inputs_path, list):
            alerting_inputs_path = [Path(p) for p in alerting_inputs_path]
        else:
            alerting_inputs_path = []

        # read the raw report data
        raw_report_data = None
        if raw_report_path == Path("."):
            raw_report_path = None

        if raw_report_path:
            try:
                with raw_report_path.open("r") as f:
                    rep = yaml.safe_load(f)

                    #rep["dedup_crash_report"]["dedup_tokens_shellphish"] = {}
                    #rep["run_pov_result"]["pov"]["organizer_crash_eval"] = {}
                    #rep["run_pov_result"]["pov"]["dedup_crash_report"]["dedup_tokens_shellphish"] = {}
                    #rep["run_pov_result"]["pov"]["organizer_crash_eval"]["code_label"] = ""
                    #rep["run_pov_result"]["pov"]["organizer_crash_eval"]["significance"] = 0
                    #rep["run_pov_result"]["pov"]["organizer_crash_eval"]["significance_message"] = ""
                    #rep["run_pov_result"]["pov"]["organizer_crash_eval"]["crash_state"] = ""
                    #rep["run_pov_result"]["pov"]["dedup_crash_report"]["dedup_tokens_shellphish"]["code_label"] = ""
                    #rep["run_pov_result"]["pov"]["dedup_crash_report"]["dedup_tokens_shellphish"]["significance"] = ""
                    #rep["run_pov_result"]["pov"]["dedup_crash_report"]["dedup_tokens_shellphish"]["significance_message"] = ""
                    #rep["run_pov_result"]["pov"]["dedup_crash_report"]["dedup_tokens_shellphish"]["crash_state"] = ""

                    pov_report = RepresentativeFullPoVReport.model_validate(rep)

                # get the pov_report_data which is the content of the pov report
                pov = pov_report.run_pov_result.pov
                raw_report_data = pov.crash_report.raw_report or pov.unparsed

                if isinstance(raw_report_data, bytes):
                    raw_report_data = raw_report_data.decode("utf-8", errors="ignore")
            except yaml.YAMLError:
                with open(raw_report_path, "r") as f:
                    raw_report_data = f.read()

        aicc_program = AICCProgram.from_files(
            source_root,
            target_root,
            project_metadata_path,
            report_yaml_path,
            function_indices,
            function_json_dir,
            indices_by_commit=indices_by_commit,
            functions_by_commit_jsons_dir=changed_func_by_commit,
            delta_mode=delta_mode,
            crashing_input_paths=alerting_inputs_path,
            local_run=local_run,
            coverage_build_project_path=coverage_build_project_path,
            patch_request_meta=patch_request_meta,
            bypassing_input_path=bypassing_inputs_path,
            should_init_resolver=True,
        )
        # read the kumushi report
        kumushi_clusters = None
        if kumushi_report_path:
            kumushi_report_path = Path(kumushi_report_path)
            if kumushi_report_path.exists() and kumushi_report_path.is_file():
                kumushi_clusters = load_clusters_from_yaml(kumushi_report_path, aicc_program)

        patcher = cls(
            aicc_program,
            patch_output_dir=patch_output_dir,
            patch_metadata_output_dir=patch_metadata_output_dir,
            crashing_commit=crashing_commit,
            patch_planning=patch_planning,
            indices_by_commit=indices_by_commit,
            changed_func_by_commits=changed_func_by_commit,
            function_indices=function_indices,
            function_json_dir=function_json_dir,
            local_run=local_run,
            kumushi_clusters=kumushi_clusters,
        )
        return patcher
