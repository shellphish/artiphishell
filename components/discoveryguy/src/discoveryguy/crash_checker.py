import subprocess
import os
import fuzzing
import random
import logging

from rich import print
from .config import Config
from .suppress import maybe_suppress_output

from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject
# from ..exceptions.errors import PatchedCodeStillCrashes

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class CrashChecker:
    def __init__(self, cps, aggregated_harness_info, local_run=True):
        self.__name__ = "CrashChecker"

        self.aggregated_harness_info = aggregated_harness_info
        self.harness_infos = self.aggregated_harness_info['harness_infos']
        self.build_configurations = self.aggregated_harness_info['build_configurations']
        self.cps = cps
        use_task_service = False if local_run else True

        self.bld_config_to_cp = {}
        for build_config_id, build_config in self.build_configurations.items():
            for cp in self.cps:
                if build_config_id in str(cp.project_path).split("/"):
                    self.bld_config_to_cp[build_config_id] = (cp, build_config['sanitizer'])

        if Config.is_local_run:
            for cp in self.cps:
                cp.build_builder_image()
                cp.build_runner_image()

    def get_right_harness_info(self, build_id, harness_name):
        '''
        Example of a harness_info
        'harness_infos': {
            '99d2fb5730e33b2233406d2868695174': {
                'architecture': 'x86_64',
                'build_configuration_id': '98e1fcfa58812736c398048a98bba5f5',
                'cp_harness_binary_path': 'out/filein_harness',
                'cp_harness_name': 'filein_harness',
                'entrypoint_function': None,
                'project_harness_metadata_id': 'c5c67c8b2afc5ac80e928ea4dee1431f',
                'project_id': 'c09bb6b954394fa6943ca823864764e5',
                'project_name': 'mock-cp',
                'sanitizer': 'address',
                'source_entrypoint': None
            }
        '''
        for harness_info_id, harness_info in self.harness_infos.items():
            if harness_info['build_configuration_id'] == build_id and harness_info['cp_harness_name'] == harness_name:
                return harness_info_id, harness_info

        return None

    def check_input(self, project_id, crashing_input_path, harness_name):
        # Run the cp with the crashing input!
        # try:
            # from .utils import run_fuzzer
            # harness_info = None
            # cp = None
            # for build_id, harness in self.harness_infos.items():
                # if harness['cp_harness_name'] == harness_name and harness['sanitizer'] == 'address':
                    # harness_info = harness
                    # build_configuration_id = harness['build_configuration_id']
                    # #NOTE: pls tell me if you change this objecyt structure, I will cry
                    # cp = self.bld_config_to_cp[build_configuration_id][0]
                    # break
            # crashing_input_dir = os.path.dirname(crashing_input_path)
            # fuzzer_uid = run_fuzzer(cp, harness_info, crashing_input_dir, timeout=120)
        # except Exception as e:
            # print(f"Fuzzing failed due to an error: {e}")
            # print("GO GO GO !!!!!!!!!!!!!!!!!!!!")
        logger.info(f"*****************************************************************")
        logger.info(f"Running {harness_name} with crashing input: {crashing_input_path}")
        logger.info(f"*****************************************************************")
        res = None

        # Try all the build configurations until one crashes!
        for build_id, v in self.bld_config_to_cp.items():
            cp = v[0]
            sanitizer = v[1]
            try:
                logger.info(f"💣->💥? Running crashing input on build {build_id} with sanitizer {sanitizer}...")
                with maybe_suppress_output():
                    res = cp.run_pov(harness_name, data_file=crashing_input_path, sanitizer=sanitizer, timeout=60)

            except subprocess.TimeoutExpired:
                logger.warning(f'The challenge project timed out during execution using build {build_id}...')
                continue
            except Exception as e:
                logger.warning(f"Error running input {crashing_input_path} on build {build_id}: {e}")
                continue
            if res.pov.triggered_sanitizers != []:
                # NOTE: 💥 in this case we crashed!
                harness_info_id, harness_info = self.get_right_harness_info(build_id, harness_name)
                return (True, res, harness_info_id, harness_info)
            else:
                # NOTE: 😢 we did not crash, so we return False
                continue
        
        return (False, res, None, None)


class CrashCheckerSimple:
    def __init__(self, cp, local_run=True):
        self.__name__ = "CrashCheckerSimple"

        use_task_service = False if local_run else True

        # NOTE: this is a project BUILT with debug artifacts (for C) or jazzer shellphish (for Java)
        self.cp = cp

        if Config.is_local_run:
            self.cp.build_builder_image()
            self.cp.build_runner_image()


    def check_input(self, project_id, crashing_input_path, harness_name, sanitizer):
        # Run the cp with the crashing input!
        logger.info(f"💣->💥? Running {harness_name} with crashing input: {crashing_input_path}")
        res = None

        try:
            res = self.cp.run_pov(harness_name, data_file=crashing_input_path, timeout=60, sanitizer=sanitizer)
        except subprocess.TimeoutExpired:
            logger.warning(f'The challenge project timed out during execution...')
            return (False, res)
        except Exception as e:
            logger.warning(f"Error running input {crashing_input_path}: {e}")
            return (False, res)

        if res.pov.triggered_sanitizers != []:
            # NOTE: 💥 in this case we crashed!
            return (True, res)
        else:
            # NOTE: 😢 we did not crash, so we return False
            return (False, res)