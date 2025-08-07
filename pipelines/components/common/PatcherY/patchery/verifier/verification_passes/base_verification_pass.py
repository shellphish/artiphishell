from typing import Tuple, Optional, Dict, Any, Type

from patchery.data import Patch, ProgramInfo


class BaseVerificationPass:
    def __init__(
        self,
        prog_info: ProgramInfo,
        patch: Patch,
        must_validate: bool = True,
        requires_executor: bool = False,
        kernel_pass: bool = False,
        base_prog_class: Optional[Type[ProgramInfo]] = None,
        cache=None,
        **kwargs,
    ):
        self._prog_info = prog_info
        self._patch = patch
        self._requires_executor = requires_executor
        self._kernel_pass = kernel_pass
        self._base_prog_class = base_prog_class

        self.must_validate = must_validate
        self.cache = cache

        self.verified = False
        self.reasoning = None
        self.cost = 0.0

    def should_skip(self) -> Tuple[bool, str]:
        if self._kernel_pass and not self._prog_info.has_reproducer:
            return True, "Not a kernel program. Skipping verification."

        if self._base_prog_class is not None and not isinstance(self._prog_info, self._base_prog_class):
            return True, f"Program is not an instance of {self._base_prog_class.__name__}. Skipping verification."

        return False, ""

    def verify(self):
        # this is not a skip, it is instead a failure
        if self._requires_executor and not self._prog_info.executor:
            self.verified = False
            self.reasoning = "No executor found. Verification failed."
            return

        self.verified, self.reasoning = self._verify()

    def _verify(self) -> Tuple[bool, Any]:
        raise NotImplementedError("Subclasses must implement this method.")
