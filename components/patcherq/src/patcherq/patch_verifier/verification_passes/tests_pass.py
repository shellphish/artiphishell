import logging
import os
import tempfile

from pathlib import Path

from ..exceptions.errors import PatchedCodeDoesNotPassTests
from .base_pass import BaseVerificationPass
from ...utils.supress import maybe_suppress_output

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class TestsVerificationPass(BaseVerificationPass):
    '''
    This pass is responsible for verifying that the patched code
    passes all the tests that are provided 
    (i.e., no breaking changes to the code).
    '''
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.__name__ = "TestsVerificationPass"
        self.git_diff = kwargs.get('git_diff')
        self.use_task_service = os.getenv('LOCAL_RUN') != 'True'

    def run(self) -> bool:
        
        git_diff_file_at = Path(tempfile.mktemp(prefix="patch."))
        git_diff_file_at.touch()

        with git_diff_file_at.open('w') as output_file:
            output_file.write(self.git_diff)

        # the logs for the failure can be found in test_result.stdout and stderr
        with maybe_suppress_output():
            test_result = self.cp.run_tests(
                patch_path=git_diff_file_at,
                sanitizer=self.all_args['sanitizer_to_build_with'],
                print_output=False,
            )
        if test_result.tests_exist:
            if test_result.all_passed:
                return True
            else:
                stderr = test_result.stderr
                stdout = test_result.stdout

                logger.info("========= TESTING PROCESS STDERR START =========")
                logger.info(stderr)
                logger.info("====================================")
                logger.info("========= TESTING PROCESS STDOUT START =========")
                logger.info(stdout)
                logger.info("====================================")
                
                # Create a temporary file
                with tempfile.NamedTemporaryFile(delete=False) as stderr_log:
                    logger.info("Temporary file for stderr created at %s", stderr_log.name)
                    stderr_log.write(b'\n===TESTING PROCESS STDERR START===\n')
                    stderr_log.write(stderr.encode())
                    stderr_log.write(b'===TESTING PROCESS STDERR END===\n')
                    stderr_log.write(b'\n===TESTING PROCESS STDOUT START===\n')
                    stderr_log.write(stdout.encode())
                    stderr_log.write(b'===TESTING PROCESS STDOUT END===\n')

                raise PatchedCodeDoesNotPassTests(stderr_log.name)
        else:
            logging.info('No tests were found. Assuming the patch is correct.')

        return True
