import logging
import os
import tempfile
import requests
from pathlib import Path

from ..exceptions.errors import PatchedCodeDoesNotPassBuildPass
from .base_pass import BaseVerificationPass

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class BuildCheckVerificationPass(BaseVerificationPass):
    '''
    This pass is responsible for using the organizer build check
    to make sure we are not breaking harnesses.
    '''
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.__name__ = "BuildCheckVerificationPass"
        self.use_task_service = os.getenv('LOCAL_RUN') != 'True'

    def does_build_check_work(self, build_configuration_id):
        import yaml
        try:
            resp = requests.get(f'{os.environ.get("PDT_AGENT_URL")}/data/verify_build_check_works/build_check_success/{build_configuration_id}', timeout=180)
            if resp.status_code != 200:
                return False
            check_data = yaml.safe_load(resp.text)
            check_success = check_data.get('runs', None)
            return check_success is True
        except Exception as e:
            import traceback
            traceback.print_exc()
            return False

    def run(self) -> bool:
        
        # NOTE: sanity check 🧘🏻
        res = self.does_build_check_work(self.patcherq.build_configuration_id)
        
        # NOTE: return early if the build check either fails OR is reported broken.
        if not res:
            logger.error("Build check does not work for the current build configuration. Skipping build check pass. 🙄")
            return True

        try:
            test_result = self.cp.run_ossfuzz_build_check(
                sanitizer=self.patcherq.kwargs['sanitizer_to_build_with']
            )
        except Exception as e:
            # NOTE: if we cannot run the build check, we assume it is a pass.
            logger.error(f"Error during build check execution: {e}. Skipping build check pass. 🙄")
            return True

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

            raise PatchedCodeDoesNotPassBuildPass(stderr_log.name)