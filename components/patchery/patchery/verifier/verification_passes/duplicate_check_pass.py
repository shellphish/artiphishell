import logging
import typing

from .base_verification_pass import BaseVerificationPass
if typing.TYPE_CHECKING:
    from ..patch_verifier import PatchVerifier


_l = logging.getLogger(__name__)


class DuplicateVerificationPass(BaseVerificationPass):
    def __init__(self, *args, verifier: "PatchVerifier" = None, **kwargs):
        self._verifier = verifier
        assert self._verifier is not None, "DuplicateVerificationPass requires a verifier"

        self._duplicate_heat_penalty = 0.1
        super().__init__(*args, **kwargs)

    def _verify(self):
        if self._patch in self._verifier.failed_patches:
            _l.info("📋 Patch is a duplicate of a previously failed patch! Turning up heat by %f", self._duplicate_heat_penalty)
            self._verifier.failure_heat += self._duplicate_heat_penalty
            return False, f"The Patch is a duplicate of a previously failed patch!\n"

        return True, "Patch is unique!"