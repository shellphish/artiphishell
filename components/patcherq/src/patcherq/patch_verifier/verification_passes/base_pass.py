

from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject

class BaseVerificationPass:
    def __init__(self, cp: OSSFuzzProject, clean_cp: OSSFuzzProject, patch: dict, git_diff, functions_in_patch, language, root_cause_report, patcherq, all_args: dict):
        self.__name__ = "__BaseVerificationPass__"
        self.cp = cp
        self.clean_cp = clean_cp
        # This is a structured version of the patch
        self.patch = patch
        # This is the raw git diff applied to the original repo
        self.git_diff = git_diff
        self.functions_in_patch = functions_in_patch
        self.all_args = all_args
        self.language = language
        self.patcherq = patcherq
        self.root_cause_report = root_cause_report

    def run(self):
        raise NotImplementedError()