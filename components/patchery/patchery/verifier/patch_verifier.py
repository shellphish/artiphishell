import logging
import os
import tempfile
import typing
from pathlib import Path
from typing import Any, Tuple, List, Type
from kumushi.aixcc import AICCProgram

from crs_telemetry.utils import get_otel_tracer

from .verification_passes import (
    BaseVerificationPass,
    CompileVerificationPass,
    AlertEliminationVerificationPass,
    SyzCallerVerificationPass,
    FunctionalityVerificationPass,
    DuplicateVerificationPass,
    NewCodeCheckPass,
    RegressionPass
)
from .verification_passes.fuzz_pass import FuzzVerificationPass
from .verification_passes.ossfuzz_build_check_pass import OssFuzzBuildCheckPass
from .. import Patch

if typing.TYPE_CHECKING:
    from patchery.patcher import Patcher

tracer = get_otel_tracer()
_l = logging.getLogger(__name__)


class PatchVerifier:
    DEFAULT_PASSES = [
        (DuplicateVerificationPass, True),
        (NewCodeCheckPass, True),
        (CompileVerificationPass, True),
        (OssFuzzBuildCheckPass, True),
        (AlertEliminationVerificationPass, True),
        (RegressionPass, True),
        (FunctionalityVerificationPass, True),
        (SyzCallerVerificationPass, False),
        (FuzzVerificationPass, True),
    ]

    def __init__(self, prog_info: AICCProgram, initial_failure_heat=0.0, passes=None, smart_mode=False, patcher=None):
        self._prog_info = prog_info
        self._passes: List[Tuple[Type[BaseVerificationPass], bool]] = passes or self.DEFAULT_PASSES
        self.smart_mode = smart_mode
        self._patcher: "Patcher" = patcher

        self.cost = 0.0
        self.failure_heat = initial_failure_heat
        self.failed_patches = set()

        # shared data for passes
        os.makedirs(f"/shared/patchery/{self._prog_info.poi_report.project_id}", exist_ok=True)
        self.regression_fuzzing_dir = Path(
            tempfile.TemporaryDirectory(dir=f"/shared/patchery/{self._prog_info.poi_report.project_id}", prefix="regression_fuzz_").name
        )

    @tracer.start_as_current_span("patchery.verify")
    def verify(self, patch: Patch) -> Tuple[bool, Any]:
        verified = True
        reasoning = None
        for pass_cls, should_run in self._passes:
            if self._patcher and not self._patcher.should_work:
                _l.warning("The patcher is shutting down all threads! Stopping verification...")
                verified = False
                reasoning = "Patcher is shutting down"
                break

            verifier = pass_cls(self._prog_info, patch, verifier=self, smart_mode=self.smart_mode)
            force_skip, skip_reason = verifier.should_skip()
            if not should_run or force_skip:
                skip_reason = skip_reason if force_skip else "Pass disabled"
                _l.info(f"🟡 Skipping {pass_cls.__name__} because: {skip_reason}")
                continue

            _l.info(f"🔬 Running {pass_cls.__name__} now...")
            try:
                verifier.verify()
            except Exception as e:
                _l.error("❌ %s failed with an exception: %s... skipping and assuming pass.", pass_cls.__name__, e, exc_info=True)
                if not verifier.FAIL_ON_EXCEPTION:
                    continue
                # exception had an internal error, but is dangerous enough to fail the verification process
                verifier.verified = False
                verifier.reasoning = f"Exception during verification: {e}"

            self.cost += verifier.cost
            if not verifier.verified:
                verified = False
                reasoning = verifier.reasoning
                self.failed_patches.add(patch)
                _l.info(f"❌ {pass_cls.__name__} failed: {reasoning}")
                if verifier.must_validate:
                    break

            _l.info(f"✅ {pass_cls.__name__} passed")

        _l.info("✅ 🎉 Patch is verified!!!!" if verified else f"❌ 🤡 Patch is NOT verified: {reasoning}")
        return verified, reasoning
