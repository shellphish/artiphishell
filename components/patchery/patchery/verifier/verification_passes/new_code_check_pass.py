import logging

from unidiff import PatchSet

from .base_verification_pass import BaseVerificationPass

_l = logging.getLogger(__name__)


class NewCodeCheckPass(BaseVerificationPass):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def _measure_change(self, hunk, change_symbol: str):
        number = 0
        change_symbol = change_symbol.strip()
        lines = [line.strip() for line in hunk.__str__().split("\n") if line.startswith(change_symbol)]
        for line in lines:
            if line != change_symbol:
                number += 1
        return number

    def _verify(self):
        if self._patch.diff is not None:
            added_line_number = 0
            deleted_line_number = 0
            patch_set = PatchSet(self._patch.diff)
            for patch_data in patch_set:
                for hunk in patch_data:
                    if hunk is None:
                        continue
                    added_line_number += self._measure_change(hunk, "+")
                    deleted_line_number += self._measure_change(hunk, "-")
            
            if (added_line_number + deleted_line_number) == 0:
                return False, "Patch is empty, it only contains empty lines. You must generate actual valid code in the patch."

        return True, "Patch is different"
            
