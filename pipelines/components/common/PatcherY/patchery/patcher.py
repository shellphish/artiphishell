from typing import Optional, List
from pathlib import Path
import logging
import math
import os
import git
import json
import re

from .verifier import PatchVerifier
from .generator import LLMPatchGenerator, LLMPromptingStyles, InvariantLLMPatchGenerator
from .data import ProgramInfo, ProgramPOI, AICCProgramInfo, InvarianceReport, JAZZER_CMD_INJECT_STR
from .report_analyzer import ReportAnalyzer, ReportType
from .utils import absolute_path_finder, pois_filepath_abs
from patchery.code_parsing import CodeParser

_l = logging.getLogger(__name__)


class Patcher:
    def __init__(
        self,
        program_info: ProgramInfo,
        max_patches=1,
        max_attempts=10,
        max_pois=8,
        max_func_size=900,
        use_report_analyzer=False,
        force_llm_report_analysis=False,
        restore_src=True,
        prompting_style: Optional[LLMPromptingStyles] = None,
        require_invariance=False,
        crashing_commit=None,
        indices_by_commit=None,
        changed_func_by_commits=None,
        func_indices: Optional[Path] = None,
        func_json_dir=None,
    ):
        self.program_info = program_info
        self.program_info.setup_program()

        self.max_patches = max_patches
        self.max_attempts = max_attempts
        self.max_pois = max_pois
        self.max_func_size = max_func_size

        self.use_report_analyzer = use_report_analyzer
        self.force_llm_report_analysis = force_llm_report_analysis
        self.prompting_style = prompting_style
        self.restore_src = restore_src
        self.require_invariance = require_invariance
        self.crashing_commit = crashing_commit

        self.indices_by_commit = indices_by_commit
        self.changed_func_by_commits = changed_func_by_commits
        self.func_indices = func_indices
        self.func_json_dir = func_json_dir
        self.total_cost = 0.0

    def _restore_src(self):
        _l.debug("Restoring the source code...")
        repo = git.Repo(self.program_info.source_root)
        repo.git.reset("--hard")
        _l.debug("Source code restored")

    def _filter_bad_pois(self, pois: List[ProgramPOI]) -> List[ProgramPOI]:
        """
        Filter out the POIs that are not in the source code.
        """
        if not pois:
            _l.critical("No POIs found.")
            return []

        good_pois = []
        for poi in pois:
            if poi.file is None:
                _l.warning(f"POI {poi} does not have a file. Skipping.")
                continue

            if not poi.function:
                _l.warning(f"POI {poi} does not have a function. Skipping.")
                continue

            if "LLVMFuzzerTestOneInput" in poi.function:
                _l.warning(f"POI {poi} is an LLVMFuzzerTestOneInput function. Skipping.")
                continue

            good_pois.append(poi)

        return good_pois

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
        if self.require_invariance:
            temperature += 0.5

        if temperature >= 1.0:
            temperature = 0.99
        if temperature < 0.0:
            temperature = 0.0
        return temperature
        

    def _gen_and_verify_core(
        self,
        poi: ProgramPOI = None,
        index: int = 0,
        report=None,
        patch_generator: LLMPatchGenerator = None,
        patch_verifier: PatchVerifier = None,
        invariance_report=None,
        **kwargs,
    ):
        failed_patch = None
        total_runs = 0
        src_just_restored = False
        patches = []
        cost = 0.0
        patch_verifier.failure_heat = 0.0
        patch_generator.temperature = 0.0 if not self.require_invariance else 0.5
        # expert reasoning on by default. maybe
        patch_generator.use_expert_reasoning = True
        _l.debug(f"Run settings: total_runs={total_runs}, max_attempts={self.max_attempts}")
        while (len(patches) < self.max_patches) and total_runs < self.max_attempts:
            total_runs += 1

            # calculate the temperature for the patch generation
            temperature = 0.0
            temperature += self._heat_sum(total_runs, patch_verifier.failure_heat)
            patch_generator.temperature = temperature
            _l.debug(f"🌡️  Setting Temperature: {temperature}")
            if (temperature >= 0.1) and not self.require_invariance:
                _l.info(f"Temperature is non-zero, turning reasoning off!")
                patch_generator.use_expert_reasoning = False

            src_just_restored = False
            _l.info(f"🤖 Starting run {total_runs}/{self.max_attempts} for POI(func={poi.function}) {index}/{self.max_pois} ...")
            _l.info(f"🤖 Generating patch {len(patches) + 1}/{self.max_patches}...")
            patch = patch_generator.generate_patch(
                poi, report, failed_patch=failed_patch, invariance_report=invariance_report, **kwargs
            )
            cost += patch_generator.cost
            
            if patch is None:
                _l.error("🚫 Patch generation failed.")
                continue

            verified, reasoning = patch_verifier.verify(patch)
            cost += patch_verifier.cost
            if self.restore_src:
                src_just_restored = True
                self._restore_src()

            if verified:
                patches.append(patch)
                break
            else:
                failed_patch = patch
                failed_patch.reasoning = reasoning

        if total_runs >= self.max_attempts:
            _l.critical(f"Max runs reached. Could not generate {self.max_patches} patch(es).")

        if self.restore_src and not src_just_restored:
            self._restore_src()

        return patches, cost

    def generate_verified_patches(
        self, pois: List[ProgramPOI] = None, report=None, invariance_report: Optional[InvarianceReport] = None, **kwargs
    ):
        """
        Given a PoI or a report, only generate patches which are verified.
        TODO: Add support for multiple PoIs.

        :param pois:
        :param report:
        :param invariance_report:
        :return:
        """
        report_cost = 0.0
        pois = pois or []
        for poi in pois:
            if not poi.report:
                poi.report = report
        if pois and not report:
            report = pois[0].report


        use_invariance = self.require_invariance and invariance_report is not None
        needs_new_pois = (
            self.force_llm_report_analysis
            or self.use_report_analyzer
            or (not pois)
            or use_invariance
            or self.crashing_commit
        )
        if needs_new_pois and report is not None:
            if use_invariance and pois:
                _l.warning("Invariance report is provided, but we also got POIs. Ignoring the POIs.")

            if self.force_llm_report_analysis:
                report_type = ReportType.BACKTRACE
            elif use_invariance:
                report_type = ReportType.INVARIANCE
            else:
                report_type = None
            report_analyzer = ReportAnalyzer(
                report if not use_invariance else invariance_report,
                report_type=report_type,
                prog_info=self.program_info,
                pois=pois,
                crashing_commit=self.crashing_commit,
                indices_by_commits=self.indices_by_commit,
                changed_func_by_commits=self.changed_func_by_commits,
                function_indices=self.func_indices,
                func_json_dir=self.func_json_dir,
            )
            # report_analyzer.analyze()
            report_cost = report_analyzer.cost
            if report_analyzer.new_pois:
                pois = report_analyzer.new_pois
                if report_type == ReportType.INVARIANCE and report is not None:
                    # for invariance, the original report (not invariance, probably ASAN) takes priority for the
                    # report property of POIs because it's more accurate.
                    for poi in pois:
                        poi.report = report

            if report_analyzer.sanitizer_string is not None and isinstance(self.program_info, AICCProgramInfo):
                self.program_info.sanitizer_string = report_analyzer.sanitizer_string

        # filter some bad pois real quick before we start the patch generation
        pois = self._filter_bad_pois(pois)
        pois_filepath_abs(self.program_info.source_root, pois)
        if not pois:
            raise ValueError("Unable to generate patches without PoIs or a report.")

        if len(pois) > self.max_pois:
            _l.warning(
                "The max allowed pois are %d, but we have %d pois. Truncating the pois...",
                self.max_pois,
                len(pois),
            )
            pois = pois[: self.max_pois]

        _l.info(f"{len(pois)} pois are feeding into LLM patch generator ...")
        patch_generator = (
            LLMPatchGenerator(self.program_info, prompt_style=self.prompting_style)
            if not self.require_invariance
            else InvariantLLMPatchGenerator(self.program_info)
        )
        patch_verifier = PatchVerifier(self.program_info)
        # TODO: add multi-core support in the future?
        total_runs = len(pois) * self.max_attempts

        for index, poi in enumerate(pois):
            _l.info(
            f"we have {len(pois)} pois. Per poi we attempt {self.max_attempts} attempts. In total we try {total_runs} times.")
            if not poi.func_src:
                if use_invariance:
                    if (not self.func_indices) or (not Path(self.func_indices).exists() and self.func_indices is not None):
                        _l.critical("Non function indices found. Bailing Out!")
                        return None
                    with open(self.func_indices, "r") as f:
                        func_indices = json.load(f)
                        
                    if invariance_report.function_index is None:
                        _l.warning(f"Function index not found for poi {poi.function}.  Skip this poi.")
                        continue
                    
                    func_path = func_indices[invariance_report.function_index]
                    func_code_path = Path(self.func_json_dir) / str(func_path)

                    with open(func_code_path, 'r') as f:
                        poi.func_src = json.load(f)['code']
                else:
                    try:
                        funcparse = CodeParser(poi.file, lang=self.program_info.lang)
                        func_name = re.sub(r'\(.*?\)', "", poi.function)
                        funcparse.func_code(func_name)
                    except ValueError:
                        _l.warning(f"poi {poi.function} is not in {poi.file}. Skip this poi.")
                        continue

            if poi.func_src:
                func_lines = poi.func_src.splitlines()
                if len(func_lines) > self.max_func_size:
                    _l.warning(f"Function {poi.function} is too large. Skipping the POI")
                    continue

            patches, generator_cost = self._gen_and_verify_core(
                poi=poi,
                index=index,
                report=poi.report,
                patch_generator=patch_generator,
                patch_verifier=patch_verifier,
                invariance_report=invariance_report,
                **kwargs,
            )
            self.total_cost += report_cost + generator_cost
            self.total_cost = round(self.total_cost, 5)
            if patches:
                _l.info(f"🎉 {len(patches)} patch(es) generated and verified.")
                return patches
