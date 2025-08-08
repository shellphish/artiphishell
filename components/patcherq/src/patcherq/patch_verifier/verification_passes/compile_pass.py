
import os
import tempfile 
import logging

from pathlib import Path

from .base_pass import BaseVerificationPass
from ..exceptions.errors import PatchedCodeDoesNotCompile
from ...utils.supress import maybe_suppress_output

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class CompilerVerificationPass(BaseVerificationPass):
    '''
    This pass is responsible for verifying that the patched code 
    compiles successfully.
    '''
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.__name__ = "CompilerVerificationPass"
        self.sanitizer_to_build_with = kwargs.get('all_args')['sanitizer_to_build_with']
        self.git_diff = kwargs.get('git_diff')
        self.build_request_id = None
        assert(self.sanitizer_to_build_with is not None)

    def run(self):
        # NOTE: 
        #   This is operating on a COPY of the original ChallengeProject created by the constructor of the 
        #   PatchVerifier. The building process will create the artifacts in the new project directory.
        #   This artifacts are used by the next verification passes.
        logger.info("Building the patched code with sanitizer: %s", self.sanitizer_to_build_with)
        with maybe_suppress_output():
            build_result = self.cp.build_target(
                                                sanitizer=self.sanitizer_to_build_with, 
                                                patch_content=self.git_diff, 
                                                preserve_built_src_dir=True
                                                )
        
        stdout = build_result.stdout
        stderr = build_result.stderr
        passed = build_result.build_success
        self.build_request_id = build_result.build_request_id

        if not passed:
            logger.info("========= COMPILATION PROCESS STDERR START =========")
            logger.info("%s", stderr)
            logger.info("====================================")
            logger.info("========= COMPILATION PROCESS STDOUT START =========")
            logger.info("%s", stdout)
            logger.info("====================================")

            # Create a temporary file
            with tempfile.NamedTemporaryFile(delete=False) as stderr_log:
                logger.info("Temporary file for stderr created at %s", stderr_log.name)
                stderr_log.write(b'\n===COMPILATION PROCESS STDERR START===\n')
                stderr_log.write(stderr)
                stderr_log.write(b'===COMPILATION PROCESS STDERR END===\n')
                stderr_log.write(b'\n===COMPILATION PROCESS STDOUT START===\n')
                stderr_log.write(stdout)
                stderr_log.write(b'===COMPILATION PROCESS STDOUT END===\n')

            raise PatchedCodeDoesNotCompile(stderr_log.name)
        else:
            return True
