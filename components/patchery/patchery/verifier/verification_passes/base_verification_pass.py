import concurrent.futures
import logging
from typing import Tuple, Optional, Any, Type

from patchery.data import Patch
from kumushi.data import Program

_l = logging.getLogger(__name__)

class BaseVerificationPass:
    TIMEOUT = 10 * 60  # 10 minutes
    FAIL_ON_EXCEPTION = False

    def __init__(
        self,
        prog_info: Program,
        patch: Patch,
        must_validate: bool = True,
        requires_executor: bool = False,
        kernel_pass: bool = False,
        base_prog_class: Optional[Type[Program]] = None,
        cache=None,
        smart_mode: bool = False,
        **kwargs,
    ):
        self._prog_info = prog_info
        self._patch = patch
        self._requires_executor = requires_executor
        self._kernel_pass = kernel_pass
        self._base_prog_class = base_prog_class

        self.must_validate = must_validate
        self.cache = cache
        self.smart_mode = smart_mode

        self.verified = False
        self.reasoning = None
        self.cost = 0.0

    def should_skip(self) -> Tuple[bool, str]:
        #if self._kernel_pass and not self._prog_info.has_reproducer:
        #    return True, "Not a kernel program. Skipping verification."

        if self._base_prog_class is not None and not isinstance(self._prog_info, self._base_prog_class):
            return True, f"Program is not an instance of {self._base_prog_class.__name__}. Skipping verification."

        return False, ""

    def verify(self):
        if self.TIMEOUT is not None:
            _l.info(f"Timeout set to {self.TIMEOUT} seconds for verification pass {self.__class__.__name__}")
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(self._verify)
                try:
                    self.verified, self.reasoning = future.result(timeout=self.TIMEOUT)
                except concurrent.futures.TimeoutError:
                    _l.error("❌ Verification timed out after %d seconds", self.TIMEOUT)
                    raise TimeoutError(f"Verification timed out after {self.TIMEOUT} seconds")
        else:
            self.verified, self.reasoning = self._verify()

    def _verify(self) -> Tuple[bool, Any]:
        raise NotImplementedError("Subclasses must implement this method.")
