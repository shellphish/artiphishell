import logging
from typing import Any, Tuple, List, Type

from .verification_passes import (
    BaseVerificationPass,
    CompileVerificationPass,
    AlertEliminationVerificationPass,
    SyzCallerVerificationPass,
    FunctionalityVerificationPass,
    TraceInvariantPass,
    KlausVerificationPass,
    DuplicateVerificationPass,
    NewCodeCheckPass
)
from .. import Patch

_l = logging.getLogger(__name__)


class PatchVerifier:
    DEFAULT_PASSES = [
        (DuplicateVerificationPass, True),
        (NewCodeCheckPass, True),
        (CompileVerificationPass, True),
        (AlertEliminationVerificationPass, True),
        (FunctionalityVerificationPass, True),
        (TraceInvariantPass, False),
        (KlausVerificationPass, False),
        (SyzCallerVerificationPass, True),
    ]

    def __init__(self, prog_info, initial_failure_heat=0.0, passes=None):
        self._prog_info = prog_info
        self._passes: List[Tuple[Type[BaseVerificationPass], bool]] = passes or self.DEFAULT_PASSES
        
        self.cost = 0.0
        self.failure_heat = initial_failure_heat
        self.failed_patches = set()

    def verify(self, patch: Patch) -> Tuple[bool, Any]:
        verified = True
        reasoning = None
        for pass_cls, should_run in self._passes:
            verifier = pass_cls(self._prog_info, patch, verifier=self)
            force_skip, skip_reason = verifier.should_skip()
            if not should_run or force_skip:
                skip_reason = skip_reason if force_skip else "Pass disabled"
                _l.info(f"🟡 Skipping {pass_cls.__name__} because: {skip_reason}")
                continue

            _l.info(f"🔬 Running {pass_cls.__name__} now...")
            verifier.verify()
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
