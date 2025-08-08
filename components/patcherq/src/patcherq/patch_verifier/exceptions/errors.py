
import enum
from pathlib import Path

class FailureCodes(enum.Enum):
    PATCHED_CODE_DOES_NOT_COMPILE = 1
    PATCHED_CODE_STILL_CRASHES = 2
    PATCHED_CODE_DOES_NOT_PASS_TESTS = 3
    PATCHED_CODE_FAILS_LINTING = 4
    CORRUPTED_PATCH = 5
    PATCHED_CODE_HANGS = 6
    ILLEGAL_PATCH_LOCATION = 7
    PATCH_DOES_NOT_SANITIZE = 8
    PATCHED_CODE_DOES_NOT_PASS_CRITIC = 9
    PATCHED_CODE_DOES_NOT_PASS_BUILD_PASS = 10

class PatchedCodeHangs(Exception):
    def __init__(self, stderr_log, num_passed=None, new_hang=False):
        super().__init__()
        assert stderr_log is not None
        self.stderr_log = stderr_log
        self.num_passed = num_passed
        self.new_hang = new_hang
    
    def __str__(self):
        err = ''
        err += f'The code suggested for the patch hangs during execution!\n'
        if self.stderr_log:
            err += f'Full hang message at: {self.stderr_log}\n'
        return err

class PatchedCodeDoesNotCompile(Exception):
    def __init__(self, stderr_log):
        super().__init__()
        assert stderr_log is not None
        self.stderr_log = stderr_log
    
    def __str__(self):
        err = ''
        err += f'The code suggested for the patch does not compile!\n'
        if self.stderr_log:
            err += f'Full compiler error message at: {self.stderr_log}\n'
        return err

class PatchedCodeStillCrashes(Exception):
    def __init__(self, crash_report=None, num_passed=None, new_crash=False):
        super().__init__()
        self.crash_report = crash_report
        self.num_passed = num_passed
        self.new_crash = new_crash
    
    def __str__(self):
        err = ''
        err += f'The code suggested for the patch did not fix the vulnerability!\n'
        if self.crash_report:
            err += f'Crash report: {self.crash_report}\n'
        return err

class PatchedCodeDoesNotPassTests(Exception):
    def __init__(self, stderr_log):
        super().__init__()
        self.stderr_log = stderr_log
    
    def __str__(self):
        err = ''
        err += f'The code suggested for the patch does not pass the unit tests!\n'
        if self.stderr_log:
            err += f'Full test error message at: {self.stderr_log}\n'
        return err

class PatchedCodeDoesNotPassBuildPass(Exception):
    def __init__(self, stderr_log):
        super().__init__()
        self.stderr_log = stderr_log
    
    def __str__(self):
        err = ''
        err += f'The code suggested for the patch does not pass the build check! You probably broke the harnesses by changing their code (or code related to them).\n'
        if self.stderr_log:
            err += f'Full build check error message at: {self.stderr_log}\n'
        return err

class PatchedCodeDoesNotPassCritic(Exception):
    def __init__(self, feedback):
        super().__init__()
        self.feedback = feedback
    
    def __str__(self):
        err = ''
        err += f'The code suggested for the patch does not pass the critic agent!\n'
        if self.feedback:
            err += f'Feedback: {self.feedback}\n'
        return err

