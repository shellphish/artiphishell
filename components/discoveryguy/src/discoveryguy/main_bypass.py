import os
import logging
import yaml
import subprocess
import random
import re
import time
import hashlib
import agentlib
import uuid
import shutil

from typing import List, Dict, Tuple
from datetime import datetime, timedelta
from pathlib import Path
from shellphish_crs_utils.sarif_resolver import SarifResolver
from shellphish_crs_utils.function_resolver import LocalFunctionResolver, RemoteFunctionResolver
from shellphish_crs_utils.models.coverage import FunctionCoverageMap, FileCoverageMap, FUNCTION_INDEX_KEY
from shellphish_crs_utils.models.ranking import RankedFunction
from shellphish_crs_utils.models import RunImageResult
from shellphish_crs_utils.models.crs_reports import CrashingInputMetadata
from shellphish_crs_utils.models.target import HarnessInfo
from shellphish_crs_utils.models.oss_fuzz import AugmentedProjectMetadata
from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject
from shellphish_crs_utils.models.patch import BypassResultMeta
from analysis_graph.models.harness_inputs import HarnessInputNode
from agentlib.lib.common import LLMApiBudgetExceededError, LLMApiContextWindowExceededError
from neomodel import db
from analysis_graph.models.crashes import GeneratedPatch

from .analysis_graph_api import *

from .agents import PatchBypass
from .toolbox import PeekSrcSkillDumb
from .crash_checker import CrashCheckerSimple
from .utils import apply_patch_source, SeedDropperManager, AVAILABLE_PYTHON_PACKAGES

from debug_lib.agent.engine import debug_helper
from .utils import get_stacktrace
from .analysis_graph_api import AnalysisGraphAPI

from shellphish_crs_utils.oss_fuzz.project import InstrumentedOssFuzzProject
from shellphish_crs_utils.oss_fuzz.instrumentation.discoveryguy import (
    DiscoveryInstrumentation,
)


logger = logging.getLogger("discoveryguy-bypass")
logger.setLevel(logging.INFO)

from .config import Config

class DiscoveryGuyBypass:

    def __init__(self, **kwargs):
        self.kwargs = kwargs

        self.project_source = self.kwargs['project_source']
        self.patch_id = self.kwargs['bypass_patch_id']
        self.dg_id = self.kwargs['dg_id']
        self.how_many_naps = 0
        self.crash_dir_pass_to_pov = self.kwargs['crash_dir_pass_to_pov']
        self.crash_metadata_dir_pass_to_pov = self.kwargs['crash_metadata_dir_pass_to_pov']

        self.oss_fuzz_debug_target_folder = self.kwargs['oss_fuzz_debug_target_folder']
        self.base_debug_target_folder = self.kwargs['debug_build_artifact']

        # Extract info from the project augmented metadata.
        with open(self.kwargs['target_metadata'], 'r') as f:
            self.project_yaml = AugmentedProjectMetadata.model_validate(yaml.safe_load(f))
        self.project_language = self.project_yaml.language.value

        # Extract infos from the bypass_request!
        with open(self.kwargs['bypass_request'], 'r') as f:
            self.bypass_request = yaml.safe_load(f)

        self.summary = self.bypass_request.get('patch_description', '')
        self.poi_report_id = self.bypass_request["mitigated_poi_report_id"]
        self.build_request_id = self.bypass_request["build_request_id"]

        # 🧠 Lets create the analysis graph API
        self.analysis_graph_api = AnalysisGraphAPI()

        # NOTE: 🌐 fetch stuff from the analysis_graph
        patch_backoff_count = 0
        while patch_backoff_count < 4:
            try:
                self.patch = self.analysis_graph_api.get_patch_info(patch_key=self.patch_id)
                self.pois_data = self.analysis_graph_api.get_pois_data(poi_key=self.poi_report_id)
                patch_backoff_count = 69 # 💋 First try
                break
            except Exception as e:
                logger.error(f"Error fetching patch or patch data: {e}. Retrying in a bit....")
                if(patch_backoff_count < 3):
                    # lets sleep for 60 seconds and try again
                    time.sleep(60 * (patch_backoff_count + 1))
                    patch_backoff_count = patch_backoff_count + 1
                else:
                    raise e
        if self.patch is None:
            raise ValueError(f"Patch with ID {self.patch_id} not found in the analysis graph.")
        if self.pois_data is None:
            raise ValueError(f"POI data with ID {self.poi_report_id} not found in the analysis graph.")
        try:
            self.crashing_input = self.analysis_graph_api.get_crashing_input(patch_id=self.patch_id)
        except Exception as e:
            logger.error(f"Error fetching crashing input: {e}")
            self.crashing_input = ""

        self.stacktrace = get_stacktrace(self.pois_data)
        self.patched_source = apply_patch_source(self.patch, self.project_source)
        self.project_id = self.kwargs['project_id']

        self.aggregated_harness_info = self.kwargs['aggregated_harness_info_file']
        with open(self.kwargs['aggregated_harness_info_file'], "r") as file:
            self.aggregated_harness_info = yaml.safe_load(file)

        self.sanitizer = 'address' # Default sanitizer
        try:
            self.sanitizer = self.aggregated_harness_info['build_configurations'][self.build_request_id]['sanitizer']
        except Exception as e:
            logger.error(f"Error while fetching sanitizer from aggregated harness info: {e}. Using default sanitizer.")

        # NOTE: This is the harness in scope according to the bypass request
        self.harness_in_scope = HarnessInfo.model_validate(self.aggregated_harness_info['harness_infos'][self.pois_data['harness_info_id']])

        # NOTE: This is a the debug artifact of the target built with the patch applied
        self.cp_debug = OSSFuzzProject(
                                project_id=self.kwargs['project_id'],
                                augmented_metadata=self.project_yaml,
                                oss_fuzz_project_path=self.oss_fuzz_debug_target_folder,
                                project_source=self.patched_source,
                                use_task_service=False
                            )
        # NOTE: This is the original debug artifact of the target built without the patch applied
        self.cp_base = OSSFuzzProject(
                                project_id = self.kwargs['project_id'],
                                oss_fuzz_project_path=self.base_debug_target_folder,
                                augmented_metadata=self.project_yaml,
                                use_task_service=False
                            )
        ########################################################
        # 🏖️ INSTANTIATE SANDBOX AND CRASH CHECKER
        ########################################################
        self.sandbox = InstrumentedOssFuzzProject(
                                        DiscoveryInstrumentation(),
                                        oss_fuzz_project_path=self.oss_fuzz_debug_target_folder
                                    )

        self.sandbox.build_runner_image()

        self.crashChecker = CrashCheckerSimple(
                                    self.cp_debug,
                                    local_run=True
                                )
        self.baseChecker = CrashCheckerSimple(
                                    self.cp_base,
                                    local_run=True,
                                )
        ########################################################

        # ######################################################
        # 🧰 LOAD THE LLM SKILLS
        ########################################################
        # Now lets load the LLM Skills
        self.peek_src_simple = PeekSrcSkillDumb(
                                    cp = self.cp_debug,
                                )
        ########################################################

    def send_seed_to_povguy(self, seed_path):
        if type(seed_path) is str:
            seed_path = Path(seed_path)

        assert seed_path.exists(), f"Crashing seed file {seed_path} does not exist!"
        
        md5name = hashlib.md5(seed_path.read_bytes()).hexdigest()
        seed_file = Path(self.crash_dir_pass_to_pov) / md5name
        seed_meta_file = Path(self.crash_metadata_dir_pass_to_pov) / md5name

        val = dict(self.harness_in_scope)
        val['harness_info_id'] = self.pois_data['harness_info_id']
        val['fuzzer'] = 'discobypass'
        harness_data = CrashingInputMetadata.model_validate(val)
        with open(seed_meta_file, 'w') as f:
            yaml.safe_dump(harness_data.model_dump(mode='json'), f, default_flow_style=False, sort_keys=False)
        
        # Send the seed to the POV guy
        shutil.copy(seed_path, seed_file)

        logger.info(f"Sending bypass seed {seed_path} to POV guy at {seed_file}")


    def take_a_nap(self):
        # NOTE: this will make the agent nap until the next budget tick.
        logger.info(f'😴 Nap time! I will be back in a bit...')
        # Go to the next multiple of Config.nap_duration
        # For example, if Config.nap_duration is 5, and the current minute is 12,
        # we will wake up at 15.
        waking_up_at = datetime.now() + timedelta(minutes=Config.nap_duration - (datetime.now().minute % Config.nap_duration))

        while True:
            if datetime.now() >= waking_up_at:
                logger.info(f'🫡 Nap time is over! Back to work...')
                break
            else:
                time.sleep(Config.nap_snoring)

    def start(self):
        feedback = ""
        attempt_num = 0

        sandbox = self.sandbox

        script_input = str(sandbox.artifacts_dir_work)
        while attempt_num < Config.max_attempts_bypass:
            try:
                bypassAgent = PatchBypass(
                    LANGUAGE_EXPERTISE=self.project_language,
                    PATCH_CODE=self.patch,
                    SUMMARY=self.summary,
                    STACK_TRACE=self.stacktrace,
                    FEEDBACK=feedback,
                    CRASHING_INPUT=self.crashing_input)
                # In the last attempt we get the magical opus
                if attempt_num == 4:
                    bypassAgent.__LLM_MODEL__ = "claude-4-opus"
                    bypassAgent_model = "claude-4-opus"
                    bypassAgent.llm  = bypassAgent.get_llm_by_name(
                                            bypassAgent_model,
                                            **bypassAgent.__LLM_ARGS__,
                                            raise_on_budget_exception=bypassAgent.__RAISE_ON_BUDGET_EXCEPTION__
                                        )

                
                curr_llm_index = 0
                # 🧠🔄
                #############################################################################
                while True:
                    try:
                        res = bypassAgent.invoke()
                        self.how_many_naps = 0
                        exploit_report = res.value
                        script = script_input + "/script.py"

                        # 🧠🔄⛓️‍💥
                        break

                    except LLMApiContextWindowExceededError as e:
                        print(" 🚪 LLM API Context Window Exceeded for BypassGuy: ", e)
                        attempt_num = 69
                        
                        # 🧠🔄⬆️
                        exit(1)

                    except LLMApiBudgetExceededError as e:
                        print(" 💸 LLM API Budget Exceeded: ", e)
                        logger.critical(f' 😭 Exception {e} during execution of {bypassAgent.__LLM_MODEL__}!')
                        curr_llm_index += 1

                        if curr_llm_index >= len(Config.bypass_agents_llms):
                            logger.info(f' 😶‍🌫️ No more LLMs to try. BypassAgent goes to sleep!')

                            # Reset the LLM index
                            curr_llm_index = 0

                            if Config.nap_mode == True and self.how_many_naps < Config.nap_becomes_death_after:
                                self.how_many_naps += 1
                                logger.info(f'😴 Taking nap number {self.how_many_naps}...')
                                self.take_a_nap()
                                logger.info(f'🫡 Nap time is over! Back to work...')

                                # Brain surgery for bypassAgent 🧠🔬
                                bypass_agent_model = Config.bypass_agents_llms[curr_llm_index]
                                logger.info(f' 🧠🔄 Switching BypassAgent to {bypass_agent_model} model...')
                                bypassAgent.__LLM_MODEL__ = bypass_agent_model
                                bypassAgent.llm  = bypassAgent.get_llm_by_name(
                                                                                bypass_agent_model,
                                                                                **bypassAgent.__LLM_ARGS__,
                                                                                raise_on_budget_exception=bypassAgent.__RAISE_ON_BUDGET_EXCEPTION__
                                                                                )

                                # 🧠🔄▶️
                                continue
                            else:
                                total_cost = agentlib.lib.agents.agent.global_event_dumper.total_cost_per_million / 1_000_000
                                logger.info(f' 💸 Total cost of the failing discoguy process: {total_cost}\n')

                                # 🧠🔄⛓️‍💥⬆️
                                exit(1)
                        else:
                            # We switch to the next model and try again
                            bypass_agent_model = Config.bypass_agents_llms[curr_llm_index]
                            logger.info(f' 🧠🔄 Switching to {bypass_agent_model} model...')
                            bypassAgent.__LLM_MODEL__ = bypass_agent_model
                            bypassAgent.llm  = bypassAgent.get_llm_by_name(
                                                                            bypass_agent_model,
                                                                            **bypassAgent.__LLM_ARGS__,
                                                                            raise_on_budget_exception=bypassAgent.__RAISE_ON_BUDGET_EXCEPTION__,
                                                                            )

                            # 🧠🔄▶️
                            continue
                # 🧠🔄
                #############################################################################

                if exploit_report['exploit_script'] is None:
                    feedback = "The exploit script was not properlly generated, make sure you follow the format of the output that I asked for. Just fix that and don't do anything else."
                    continue

                summary = exploit_report.get('summary', None)
                if summary is None:
                    summary = "No summary provided by the agent, please check the agent's history."

                with open(script, 'wb') as f:
                    payload = exploit_report['exploit_script']
                    f.write(payload.encode())

                bash_script = os.getcwd() + "/discoveryguy/run_script.sh"
                shutil.copy(bash_script, script_input+"/run_script.sh")

                sandbox_report = sandbox.runner_image_run(f"/work/run_script.sh")

                generatedSeed = script_input + "/crash.txt"
                try:
                    if not Path(generatedSeed).exists():
                        print("[!] The script failed to generate the input. Please check the script output for errors.")
                        std_out = sandbox_report.stdout.decode('utf-8')
                        std_err = sandbox_report.stderr.decode('utf-8')
                        feedback = f"The script failed to generate the input. Please check the script output for errors.\n STDOUT: {std_out}\n STDERR: {std_err}\n. Please fix the script and try again."
                        continue
                except Exception as e:
                    print("Error while checking the generated seed: ", e)
                    feedback = "The script failed to generate the input. Please check the script output for errors."
                    continue
                shutil.copy(generatedSeed, str(self.crashChecker.cp.artifacts_dir_work)+"/pov_input")
                crash_count = 0
                for crash_iter in range(0,5):
                    crashed, crashing_output = self.crashChecker.check_input(self.project_id, generatedSeed, self.harness_in_scope.cp_harness_name, sanitizer=self.sanitizer)
                    if crashed:
                        crash_count += 1
                    if not crashed:
                        print("The script did not crash the target, we will try again")
                        break
                if crash_count == 0:
                    attempt_num += 1
                    # feedback = f"Your approach failed and is summarized here: {summary['summary']}\n. It failed with the following output while running the fuzzer {crashing_output}. I'm confident that its bypassable, you might be missing some information or the approach you took is not the right one.\n"
                    continue
                if crash_count == 5:
                    try:
                        crash_base_count = 0
                        for crash_iter in range(0,2):
                            crashed_base, crashed_output_base = self.baseChecker.check_input(self.project_id, generatedSeed, self.harness_in_scope.cp_harness_name, sanitizer=self.sanitizer)
                            if crashed_base:
                                crash_base_count += 1
                        if crash_base_count == 0:
                            feedback = "Your approach does crash the patched target, but not the base target. You found a bypass but these are specific to this bad patch, but you failed to crash the original target. This means that the patch is bypassable but we are not intested in these kind of inputs. We need to crash both the base and patched target to consider it a bypass. Please try again."
                            print("Failed to crash the base target, we will try again")
                            attempt_num += 1
                            continue
                        elif crash_base_count == 1:
                            print("Unreliable crash on the base target, we will try again")
                            feedback = "Your approach does crash the patched target, but not the base target. This means that the patch is bypassable but we are not intested in these kind of inputs. We need to crash both the base and patched target to consider it a bypass. Please try again."
                            attempt_num += 1
                    except Exception as e:
                        print("Error while checking the base target: ", e)

                    print("We found a bypass script that reliably crashes the target")
                    print("Crashing output: ", crashing_output)
                    patch_id = self.bypass_request['patch_id']
                    bypass_result_at = os.path.join(self.kwargs['bypass_result_dir'], patch_id)

                    res = bypassAgent.set_human_msg("You succeed! Now generate a brief executive summary explaining why the patch was bypassable and how you accomplish to bypass it!")
                    
                    summary = 'This patch was bypassable, but unfortunately the agent did not provide a summary.'  # Default summary in case of failure

                    # Attempt to generate a summary. If we fail we just give up.
                    try:
                        res = bypassAgent.invoke()
                        summary = res.chat_messages[-1].content
                    except Exception as e:
                        logger.info(f"Error while generating summary: {e}")

                    with open(generatedSeed, "rb") as f:
                        seed_content = bytearray(f.read())
                    
                    self.send_seed_to_povguy(generatedSeed)
                    # try:
                    #     harness_input_node = HarnessInputNode.create_node(
                    #                 harness_info_id=self.pois_data['harness_info_id'],
                    #                 harness_info=self.harness_in_scope,
                    #                 content=seed_content,
                    #                 crashing=True
                    #             )
                    #     if harness_input_node[0] is False or harness_input_node is None:
                    #         logger.info("Failed to upload the crashing seed to the analysis graph")

                    #     # TODO: upload the bypass to the analysis graphs
                    #     self.analysis_graph_api.upload_bypass_to_analysis_graph(harness_input_node[1].identifier, patch_id)

                    # except Exception as e:
                    #     logger.info(f"Error while creating HarnessInputNode or BypassResultMeta: {e}")

                    # NOTE: Nobody is using this, it's just for seeing it.
                    bypass_result_meta = BypassResultMeta(
                                                        patch_id=patch_id,
                                                        summary=summary,
                                                        crashing_input_id="bypass"
                                                        )
                    with open(bypass_result_at, 'w') as f:
                            yaml.safe_dump(bypass_result_meta.model_dump(), f, default_flow_style=False, sort_keys=False)
                    print("Bypass script successfully generated and saved at: ", bypass_result_at)
                    
                    return
                
                if crash_count > 0 and crash_count < 5:
                    print("We found a bypass script that crashes the target, but not reliably")
                    print("Crashing output: ", crashing_output)
                    attempt_num += 1
                    feedback = f"You did produce a input that crashes but not consistently, the approach you took is summarized as : {summary['summary']}\n. You should use the previous summary/history to figure out a reliable approach as the previous one failed {crash_count} times out of 5 attempts."

            except Exception as e:
                # Print the stack trace for debugging
                import traceback
                traceback.print_exc()
                attempt_num += 1
                print("An error occurred: ", e)

'''
________  .__                                               ________
\______ \ |__| ______ ____  _______  __ ___________ ___.__./  _____/ __ __ ___.__.
 |    |  \|  |/  ___// ___\/  _ \  \/ // __ \_  __ <   |  /   \  ___|  |  <   |  |
 |    `   \  |\___ \\  \__(  <_> )   /\  ___/|  | \/\___  \    \_\  \  |  /\___  |
/_______  /__/____  >\___  >____/ \_/  \___  >__|   / ____|\______  /____/ / ____|
        \/        \/     \/                \/       \/            \/       \/
'''
def main(**kwargs):
    discoveryGuy = DiscoveryGuyBypass(**kwargs)
    discoveryGuy.start()