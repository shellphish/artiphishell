
import os
import logging
import yaml
import random
import re
import time
import agentlib
import uuid
import shutil
import multiprocessing as mp

from agentlib import LocalObject, ObjectParser
from typing import List, Dict, Tuple
from rich import print
from datetime import datetime, timedelta
from pathlib import Path
import hashlib
import base64

from shellphish_crs_utils.sarif_resolver import SarifResolver
from shellphish_crs_utils.models.aixcc_api import SARIFMetadata, Assessment
from shellphish_crs_utils.function_resolver import LocalFunctionResolver, RemoteFunctionResolver
from shellphish_crs_utils.models.coverage import FunctionCoverageMap, FileCoverageMap, FUNCTION_INDEX_KEY
from shellphish_crs_utils.models.ranking import RankedFunction
from shellphish_crs_utils.models import RunImageResult
from shellphish_crs_utils.models.oss_fuzz import AugmentedProjectMetadata
from shellphish_crs_utils.models.crs_reports import POIReport
from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject
from shellphish_crs_utils.models.target import HarnessInfo
from agentlib.lib.common import LLMApiBudgetExceededError, LLMApiContextWindowExceededError, LLMApiRateLimitError
from coveragelib import Tracer
from shellphish_crs_utils.models.symbols import SourceLocation
from shellphish_crs_utils.models.crs_reports import CrashingInputMetadata
from shellphish_crs_utils.models.indexer import FunctionIndex
from analysis_graph.models.harness_inputs import HarnessInputNode

from .agents import JimmyPwn, SarifTriageGuy, SeedGenerationModel, HoneySelectAgent, SummaryAgent
from .toolbox import PeekSrcSkill, PeekDiffSkill
from .crash_checker import CrashChecker
from .utils import SeedDropperManager, HarnessResolver, HarnessFullInfo, JimmyMagicPathSimplifier, DiffResolver, CodeQLSourceLocationResolver, AVAILABLE_PYTHON_PACKAGES
from .analysis_graph_api import AnalysisGraphAPI

from coveragelib.parsers.line_coverage import C_LineCoverageParser_LLVMCovHTML

from shellphish_crs_utils.oss_fuzz.project import InstrumentedOssFuzzProject
from shellphish_crs_utils.oss_fuzz.instrumentation.discoveryguy import (
    DiscoveryInstrumentation,
)
from .config import Config, DiscoverGuyMode, CRSMode

logger = logging.getLogger("discoveryguy")
logger.setLevel(logging.INFO)
logging.getLogger("shellphish_crs_utils.function_resolver").setLevel(logging.ERROR)
logging.getLogger("shellphish_crs_utils.oss_fuzz.project").setLevel(logging.ERROR)

class DiscoveryGuy:

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.target_metadata = self.kwargs['target_metadata']
        self.target_functions_jsons_dir = self.kwargs['target_functions_jsons_dir']
        self.functions_by_file_index = self.kwargs['functions_by_file_index']
        self.function_index = self.kwargs['function_index']
        self.project_id = self.kwargs['project_id']
        self.dg_id = self.kwargs['dg_id']
        self.project_source = self.kwargs['project_source']
        self.backup_seeds_vault = self.kwargs['backup_seeds_vault']
        self.report_dir = self.kwargs['report_dir']
        self.crash_dir_pass_to_pov = self.kwargs['crash_dir_pass_to_pov']
        self.crash_metadata_dir_pass_to_pov = self.kwargs['crash_metadata_dir_pass_to_pov']
        self.oss_fuzz_debug_targets_folder = self.kwargs['oss_fuzz_debug_targets_folder']
        self.fuzz_request = {}

        if Config.crs_mode == CRSMode.DELTA:
            # In this case we also load the changed function index
            self.changed_functions_jsons_dir = self.kwargs['changed_functions_jsons_dir']
            self.changed_function_index = self.kwargs['changed_function_index']
            self.diff_file = self.kwargs['diff_file']
        else:
            self.changed_functions_jsons_dir = None
            self.changed_function_index = None
            self.diff_file = None

        # Load data from the agumented project metadata
        with open(self.target_metadata, 'r') as f:
            self.project_yaml = AugmentedProjectMetadata.model_validate(yaml.safe_load(f))
        self.project_language = self.project_yaml.language.value
        self.project_name = self.project_yaml.get_project_name()
        assert self.project_name != None

        self.aggregated_harness_info = None
        with open(self.kwargs['aggregated_harness_info_file'], "r") as file:
            self.aggregated_harness_info = yaml.safe_load(file)

        self.func_ranking = None
        if Config.discoveryguy_mode == DiscoverGuyMode.POIS or Config.discoveryguy_mode == DiscoverGuyMode.POISBACKDOOR:
            with open(self.kwargs['function_ranking'], "r") as file:
                self.func_ranking = yaml.safe_load(file)

        ########################################################
        # 📦 INSTANTIATE BUILDS
        ########################################################
        # NOTE: these are BUILT OSSFuzzProject with debug artifacts.
        self.cps_debug = []
        for debug_build in os.listdir(self.oss_fuzz_debug_targets_folder):
            # debug_build MUST be a folder
            if not os.path.isdir(os.path.join(self.oss_fuzz_debug_targets_folder, debug_build)):
                logger.warning(f"Skipping {debug_build} as it is not a directory.")
                continue
            # Get the realpath of the debug build artifact
            curr_debug_build = os.path.realpath(os.path.join(self.oss_fuzz_debug_targets_folder, debug_build))
            curr_debug_build = os.path.join(curr_debug_build, "projects", self.project_name)

            curr_cp_debug = OSSFuzzProject(
                                    project_id = self.kwargs['project_id'],
                                    # e.g.,: /shared/discoveryguy/tmp.123456/oss-fuzz/projects/nginx/
                                    oss_fuzz_project_path=curr_debug_build,
                                    augmented_metadata=self.project_yaml,
                                    use_task_service=False
                                    )
            self.cps_debug.append(curr_cp_debug)

        ########################################################
        # 🏖️ INSTANTIATE SANDBOX AND CRASH CHECKER
        ########################################################
        # NOTE: this is the sandbox environment where we are executing the script
        #       generated by the exploit developer
        self.sandbox = InstrumentedOssFuzzProject(
                                                  DiscoveryInstrumentation(),
                                                  # NOTE: this arg is here just to satisfy the interface of an OSSFuzzProject
                                                  #       this is just instantiating the sandbox environment.
                                                  oss_fuzz_project_path=self.cps_debug[0].project_path
                                                  )

        self.sandbox.build_runner_image()

        # This is the object that will check if a seed is crashing the target
        self.crashChecker = CrashChecker(
                        self.cps_debug,
                        self.aggregated_harness_info,
                        # self.oss_fuzz_debug_target_folder,
                        local_run=True
                    )

        ########################################################
        # 📑 FUNCTION RESOLVER(s)
        ########################################################
        if Config.is_local_run:
            self.func_resolver = LocalFunctionResolver(
                                                       functions_index_path=self.function_index,
                                                       functions_jsons_path=self.target_functions_jsons_dir
                                                       )
        else:
            self.func_resolver = RemoteFunctionResolver(
                                                        self.project_name,
                                                        self.project_id
                                                        )

        if Config.crs_mode == CRSMode.DELTA:
            # NOTE: This function resolver can be ONLY local as we are not hosting
            #       a service that loads the commit diff.
            self.changed_func_resolver = LocalFunctionResolver(
                functions_index_path=self.changed_function_index,
                functions_jsons_path=self.changed_functions_jsons_dir
            )
        else:
            self.changed_func_resolver = None

        ########################################################

        ########################################################
        # 💆🏻‍♂️ MANAGERS FOR MAKE EVERYTHING A LITTLE EASIER
        ########################################################
        # This is needed do safely drop the seeds into the fuzzing queue
        self.seedDropperManager = SeedDropperManager(
                                                     self.dg_id,
                                                     self.project_name,
                                                     self.aggregated_harness_info['harness_infos'],
                                                     self.backup_seeds_vault,
                                                     self.report_dir,
                                                     self.crash_dir_pass_to_pov,
                                                     self.crash_metadata_dir_pass_to_pov
                                                     )
        # To resolve codeql source location in a easy way (get back function index etc...)
        self.codeql_location_resolver = CodeQLSourceLocationResolver(self.func_resolver)

        # To be able to fetch harness information without using too many loops...
        self.harness_resolver = HarnessResolver(
                                                self.cps_debug[0], # NOTE: it is ok to just pass one here, the built_src is the same
                                                self.project_language,
                                                self.aggregated_harness_info['harness_infos'],
                                                self.func_resolver
                                                )
        # A nice object to launch neo4j queries
        self.analysis_graph_api = AnalysisGraphAPI()

        # Path simplifier to trim real paths downloaded from the analysis graph
        self.path_simplifier= JimmyMagicPathSimplifier(
                                                       self.analysis_graph_api,
                                                       self.harness_resolver,
                                                       self.func_resolver,
                                                       self.diff_file
                                                       )

        if Config.discoveryguy_mode == DiscoverGuyMode.DIFFONLY:
            self.diff_resolver = DiffResolver(self.diff_file, self.func_resolver)
        ########################################################

        # ######################################################
        # 🧰 LOAD THE LLM SKILLS
        ########################################################

        self.peek_src = PeekSrcSkill(
            function_resolver=self.func_resolver,
            cp=self.cps_debug[0], # NOTE: it is ok to just pass one here, the built_src is the same
            project_metadata=self.project_yaml,
            analysis_graph_api=self.analysis_graph_api,
            **kwargs
        )

        if Config.crs_mode == CRSMode.DELTA:
            # NOTE: this skill is only enabled in delta mode.
            self.peek_diff = PeekDiffSkill(
                func_resolver=self.func_resolver,
                changed_func_resolver=self.changed_func_resolver,
                diff_file = self.diff_file,
            )
        else:
            self.peek_diff = None

        if Config.discoveryguy_mode == DiscoverGuyMode.SARIF:
            # For sarif mode, we need to load the sarif file
            self.sarif = self.kwargs['sarif']
            self.sarif_raw_path = self.kwargs['sarif']
            self.sarif_raw = (lambda p: open(p).read())(self.sarif_raw_path)
            self.sarif_meta = SARIFMetadata.model_validate(yaml.safe_load(Path(self.kwargs["sarif_meta"]).read_text()))
            self.sarif_resolver = SarifResolver(self.kwargs['sarif'], self.func_resolver)
            self.sarif_assessment_out_path = self.kwargs['sarif_assessment_out_path']

            # Bump up attempts for sarif report exploit gen!
            Config.exploit_dev_max_attempts_per_sink += 1
            Config.exploit_dev_max_attempts_regenerate_script += 1

        self.lastest_analysis_report = ""
        # 😴 For nap mode, to keep track of how many naps we have taken
        self.how_many_naps = 0

        # keep state for jimmypwn
        self.how_many_opus = 0
        try:
            fuzz_script = open('/src/run_disco_fuzz.py','rb').read()
            # Now lets base64 encode the fuzz script
            self.fuzz_payload = base64.b64encode(fuzz_script).decode('utf-8')
        except Exception as e:
            # Lets just pass the exception
            self.fuzz_payload = None
            pass

    def generate_seed_hash(self, seed_path):
        with open(seed_path, 'rb') as f:
            seed_hash = hashlib.sha256(f.read()).hexdigest()
        return seed_hash

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

    def get_sarif_triage_summary(self) -> Tuple[str, List[FUNCTION_INDEX_KEY]]:
        sarif_results = []
        all_sarif_sinks = set()
        sariftg_summary = ''

        # Get all the results from the sarif report
        sarif_results = self.sarif_resolver.get_results()

        for sarif_id, sarif_result in enumerate(sarif_results):

            logger.info(f"🦹🏻‍♂️ Analyzing SARIF result {sarif_id} with SarifTriageGuy")

            # NOTE: We are considering the first location as the sink!
            if len(sarif_result.locations) == 0:
                logger.info("🦹🏻‍♂️ No locations found, skipping...")
                continue

            sarif_tg_guy = SarifTriageGuy(
                                        language=self.project_language,
                                        project_name=self.project_name,
                                        rule_id=sarif_result.rule_id,
                                        sarif_message=sarif_result.message,
                                        locs_in_scope=sarif_result.locations,
                                        data_flows=sarif_result.codeflows,
                                        )

            ############################################################
            # 🧠🔄 Main Reasoning Loop for SarifTriageGuy
            ############################################################
            while True:
                try:
                    res = sarif_tg_guy.invoke()
                    # NOTE: every time the invoke is successfull, we can reset the nap counter
                    self.how_many_naps = 0
                    # 🧠🔄⛓️‍💥
                    break
                except LLMApiBudgetExceededError as e:
                    logger.critical(f' 😭 LLM API budget exceeded for {sarif_tg_guy.__LLM_MODEL__}!')

                    if Config.nap_mode == True and self.how_many_naps < Config.nap_becomes_death_after:
                        self.how_many_naps += 1
                        logger.info(f'😴 Taking nap number {self.how_many_naps}...')
                        self.take_a_nap()
                        #🧠🔄▶️
                        continue
                    else:
                        total_cost = agentlib.lib.agents.agent.global_event_dumper.total_cost_per_million / 1_000_000
                        logger.info(f' 💸 Total cost of the failing discoveryguy process: {total_cost}\n')
                        # 🧠🔄⛓️‍💥
                        self.exit_and_clean(1)
                except Exception as e:
                    logger.error(f"Error in sarif_tg_guy.invoke(): {e}")
                    # 🧠🔄⛓️‍💥
                    break
            ############################################################

            try:
                sariftg_summary = res.value['summary']
            except Exception as e:
                sariftg_summary = "No summary could be generated. You are on your own!"

            logger.info(f"🦹🏻‍♂️ Got summary from SarifTriageGuy: {sariftg_summary}")

            sink_index:FUNCTION_INDEX_KEY = sarif_result.locations[0].keyindex
            #sink_full_info:FunctionIndex = self.func_resolver.get(sink_index)
            #function_name = self.func_resolver.get_funcname(sink_index)

            all_sarif_sinks.add(sink_index)

        return sariftg_summary, list(all_sarif_sinks)

    def get_ranked_functions(self) -> List[FUNCTION_INDEX_KEY]:
        keys = [item['function_index_key'] for item in self.func_ranking['ranking']]
        ranked_funcs = list(self.func_resolver.find_matching_indices(scope="compiled", indices=keys)[0].values())
        if len(ranked_funcs) > Config.max_pois_to_check:
            ranked_funcs = ranked_funcs[:Config.max_pois_to_check]
        return ranked_funcs

    def get_suspicious_funcs(self) -> List[FUNCTION_INDEX_KEY]:
        keys = [ x for x in self.func_ranking['sus_funcs'] if x != None]
        return keys

    def get_sinks_from_diff(self) -> List[FUNCTION_INDEX_KEY]:
        keys = self.diff_resolver.get_sinks()
        return keys

    # def get_closest_benign_seed_to_sink(self, path):
    #     for node in path[::-1]:
    #         seed = self.analysis_graph_api.get_benign_input_for_function(node['name'])
    #         if len(seed) > 0:
    #             logger.info(f" 🌱 Found a benign seed for {node['name']} on the path to the sink")
    #             seed_content = seed[0][0].content_escaped
    #             return seed_content.encode().decode('unicode_escape')[0:Config.max_bytes_for_benign_seed_template], node['name']
    # def get_closest_benign_seed_to_sink(self, path):
    #     for node in path[::-1]:
    #         seed = self.analysis_graph_api.get_benign_input_for_function(node['name'])
    #         if len(seed) > 0:
    #             logger.info(f" 🌱 Found a benign seed for {node['name']} on the path to the sink")
    #             seed_content = seed[0][0].content_escaped
    #             return seed_content.encode().decode('unicode_escape')[0:Config.max_bytes_for_benign_seed_template], node['name']

    #     return None, None
    #     return None, None

    def run_seed_generation(self, seedAgent:SeedGenerationModel, reached_harnesses:dict, sink_index_key, report_attempt_no, seed_attempt_no):
        id = uuid.uuid4()
        sandbox = self.sandbox
        script_input = str(sandbox.artifacts_dir_work)
        exploit_script = ""
        function_name = self.func_resolver.get_funcname(sink_index_key)
        bad_error = 0

        ########################################################
        # 🐍👨🏻‍💻💰🔄
        ########################################################
        while True:
            try:
                logger.info(f"🦹🏻‍♂️ Starting seedAgent.invoke() with {seedAgent.__LLM_MODEL__} model...")
                res = seedAgent.invoke()
                # NOTE: every time the invoke is successfull, we can reset the nap counter
                self.how_many_naps = 0

                # Extract the report from the ExploitDeveloper agent using our parser!
                exploit_script = res.value["exploit_script"]
                logger.info(f"🦹🏻‍♂️ Got pwn.py")
                script = script_input + "/script.py"

                # Save the script at the right location
                with open(script, "wb") as file:
                    payload = exploit_script
                    file.write(payload.encode())

                # 🐍👨🏻‍💻💰⛓️‍💥
                break

            except (LLMApiBudgetExceededError, LLMApiRateLimitError) as e:
                logger.critical(f' 😭 LLM API budget exceeded for {seedAgent.__LLM_MODEL__}!')
                # NOTE: WE ARE NOT SWITCHING MODEL HERE, DISCOVERYGUY MODELS MUST BE THESE.

                if Config.nap_mode == True and self.how_many_naps < Config.nap_becomes_death_after:
                    self.how_many_naps += 1
                    logger.info(f'😴 Taking nap number {self.how_many_naps}...')
                    self.take_a_nap()
                    # 🐍👨🏻‍💻💰▶️
                    continue
                else:
                    total_cost = agentlib.lib.agents.agent.global_event_dumper.total_cost_per_million / 1_000_000
                    logger.info(f' 💸 Total cost of the failing discoveryguy process: {total_cost}\n')
                    # 🐍👨🏻‍💻💰⛓️‍💥
                    self.exit_and_clean(1)

            except Exception as e:
                if bad_error == 1:
                    # 🐍👨🏻‍💻💰⛓️‍💥
                    return False, False, "Something very bad happened during seed generation. Try something else.", "", "", ""
                else:
                    logger.error(f"Error in seedAgent.invoke(): {e}")
                    logger.error("🫣 Retrying one more time in 10 seconds...")
                    time.sleep(10)
                    # NOTE: If we have an error, we just retry the invoke
                    # 🐍👨🏻‍💻💰▶️
                    if bad_error == 0:
                        bad_error = 1
                    continue
        ########################################################
        # 🐍👨🏻‍💻💰🔄
        ########################################################

        # NOTE: we are out of the loop, we have a Python script 🐍!
        #       Let's try to run the python script in the sandbox 🏖️ to
        #       produce a seed!
        bash_script = os.getcwd() + "/discoveryguy/run_script.sh"
        shutil.copy(bash_script, script_input+"/run_script.sh")

        # 🏖️
        sandbox_report = sandbox.runner_image_run(f"/work/run_script.sh")
        std_err = sandbox_report.stderr.decode()

        # Handle the case where the script fails to run
        if sandbox_report.run_exit_code == 124:
            logger.warning(f'The execution of the Pytohn script timed out!')
            feedback_for_seed_agent = f"\nYour script timed out after 60 seconds. Please make sure there are no infinite loops or long running operations in your script."
            return False, False, feedback_for_seed_agent, sandbox_report, exploit_script, ""


        elif sandbox_report.run_exit_code != 0:
            # NOTE: This is trying to detect the reason why the python script failed...
            if 'ModuleNotFoundError' in std_err:
                logger.warning(f'The execution of the Pytohn script had a ModuleNotFoundError...')
                module = std_err.replace("\n", "").split("No module named '")[1].split("'")[0]
                feedback_for_seed_agent = f"\nThe library {module} is not installed in the sandbox. Please remove it and try again with the allowed libraries. "
                feedback_for_seed_agent += "You can use the following libraries: \n"
                feedback_for_seed_agent += " ".join(AVAILABLE_PYTHON_PACKAGES)
                return False, False, feedback_for_seed_agent, sandbox_report, exploit_script, ""
            else:
                logger.warning(f'The execution of the Python had an error...')
                feedback_for_seed_agent = f"\nScript failed to run in the sandbox. Please review the analysis report and the failed scripts, and try again. {std_err}"
                logger.warning(f'The execution of the Python had an error...')
                feedback_for_seed_agent = f"\nScript failed to run in the sandbox. Please review the analysis report and the failed scripts, and try again. {std_err}"
                return False, False, feedback_for_seed_agent, sandbox_report, exploit_script, ""
        else:
            logger.info(f'✅ Successfully executed the generated Python script')

        crash_txt = str(self.sandbox.artifacts_dir_work) + "/crash.txt"
        for cp in self.crashChecker.cps:
            shutil.copy(crash_txt, str(cp.artifacts_dir_work)+"/pov_input")

        ########################################################
        # 🔄 Check if we can crash at least one harness in scope
        ########################################################
        crashed = False
        found_good_crash = False
        found_unintended_crash = False
        crashing_harness = None
        for _, harness in reached_harnesses.items():
            (crashed, crashing_output, harness_info_id, harness_info) = self.crashChecker.check_input(
                self.project_id,
                crash_txt,
                harness.bin_name
            )
            if crashed:
                # Stopping at the first harness that crashes
                # 🔄⛓️‍💥
                if harness_info_id is None:
                    # This means something went really really wrong, yoloing it.
                    # harness here is our HarnessFullInfo
                    # NOTE: I DO NOT EXPECT THIS BRANCH TO EVER HAPPEN IF WE HAVE THE RIGHT ARTIFACTS.
                    logger.warning(f' 🤮 Somehow we could not find the right harness_info_id when we crashed the challenge, this is very weird but not fatal...')
                    crashing_harness = harness
                    crashing_harness_info_id = crashing_harness.info_id
                    crashing_harness_info = self.harness_resolver.get_harness_info_by_id(crashing_harness.info_id)
                else:
                    # We have a valid HarnessInfo object (so we can successfully link to the right build and sanitize)
                    # NOTE: life is good in this else 😇
                    crashing_harness = harness
                    crashing_harness_info_id = harness_info_id
                    crashing_harness_info = harness_info
                    logger.warning(f' 👹 We crashed the target with this harness: {crashing_harness_info}')
                break
        ########################################################

        if Config.discoveryguy_mode == DiscoverGuyMode.SARIF:
            # Add the connection to the analysis graph for bundling later!
            try:
                # NOTE: crashing_harness.info_id --> this is the id of the harness as per pdt
                # NOTE: crashing_harness_info --> a HarnessInfo object
                seed_id = self.seedDropperManager.send_seed_to_analysis_graph(crashing_harness_info_id, crashing_harness_info, crash_txt, True)
                if seed_id is not None:
                    logger.info(f"🌱💾 Seed successfully added to the analysis graph with id {seed_id}")
                    try:
                        self.analysis_graph_api.link_seed_to_sarif(seed_id, self.sarif_meta.pdt_sarif_id, self.sarif_resolver)
                        logger.info(f'🌱🔗📊 Seed linked to SarifReport {self.sarif_meta.pdt_sarif_id} in the analysis graph!')
                    except Exception as e:
                        logger.error(f'🌱⛓️‍💥📊 Failed linking seeds and SarifReport...')
            except Exception as e:
                logger.error(f'🌱😢 Failed to upload seed to analysis graph...')

        ########################################################
        # 🔄 Save the seed in ALL the harnesses queue (why not!)
        ########################################################
        logger.info(f"🫳🌱 Dropping seed into all the fuzzing queues...")
        for harness in self.harness_resolver.get_all_harnesses():
            self.seedDropperManager.add_seed(harness.info_id, crash_txt)
        ########################################################

        if crashed:
            # 🔥
            if function_name in str(crashing_output):
                # NOTE: 🔥👍 in this case we are sure we covered the vulnerable function!
                found_good_crash = True
                self.seedDropperManager.send_seed_to_povguy(crashing_harness_info_id, crash_txt)
                # NOTE: accessing the bin_name through the crashing_harness is fine!
                self.seedDropperManager.backup_seed(crashing_harness.bin_name, function_name, crash_txt, report_attempt_no, seed_attempt_no, id, "succeeded")
                self.seedDropperManager.backup_crash_report(crashing_harness.bin_name, function_name, sink_index_key, seedAgent.REPORT, exploit_script, str(crashing_output.stderr), report_attempt_no, seed_attempt_no, id,  "succeeded")
                total_cost = agentlib.lib.agents.agent.global_event_dumper.total_cost_per_million / 1_000_000
                logger.info(f' 💸 discoveryguy current cost: {total_cost}\n')

                feedback_for_seed_agent = "GREAT! You have successfully generated a seed script that crashes the target function. "
            else:
                # NOTE: 🔥👀 in this case we might have triggered an unintended bug
                found_unintended_crash = True
                self.seedDropperManager.send_seed_to_povguy(crashing_harness_info_id, crash_txt)
                # NOTE: accessing the bin_name through the crashing_harness is fine!
                self.seedDropperManager.backup_seed(crashing_harness.bin_name, function_name, crash_txt, report_attempt_no, seed_attempt_no, id, "unintended")
                self.seedDropperManager.backup_crash_report(crashing_harness.bin_name, function_name, sink_index_key, seedAgent.REPORT, exploit_script, str(crashing_output.stderr), report_attempt_no, seed_attempt_no, id,  "unintended")
                feedback_for_seed_agent = f'''You cause a crash this time, but this is an unintended crash, the sink function {function_name} was not covered in the crash trace. try again. Please make sure to cover the sink function next time. Try another attack scenario. Current seed script is like this, Never use this script again, Think in a different way.
                <bad_script>
                {exploit_script}
                </bad_script>
                '''
                total_cost = agentlib.lib.agents.agent.global_event_dumper.total_cost_per_million / 1_000_000
                logger.info(f' 💸 discoveryguy current cost: {total_cost}\n')
        else:
            # 🥹
            self.seedDropperManager.backup_seed("whatever", function_name, crash_txt, report_attempt_no, seed_attempt_no, id, "failed")
            self.seedDropperManager.backup_crash_report("whatever", function_name, sink_index_key, seedAgent.REPORT, exploit_script, "N/A", report_attempt_no, seed_attempt_no, id,  "failed")
            feedback_for_seed_agent = "Crash failed, review the analysis report, mutate the script and generate the script again\n"

        try:
            self.fuzz_request[sink_index_key]['seeds'].append(self.generate_seed_hash(crash_txt))
        except Exception as e:
            print("Go! Go! Go!")

        return found_good_crash, found_unintended_crash, feedback_for_seed_agent, sandbox_report, exploit_script, crash_txt

    def run_exploit_dev(self, jimmyPwn, reached_harnesses, sink_index_key, report_attempt_no):
        feedback_for_jimmy_pwn = ""
        feedback_for_seed_agent = ""
        found_good_crash = False

        # NOTE: store all the bad scripts that are not generating a crashing script
        bad_scripts = []
        failed_scripts = []

        if Config.check_top_n_with_opus:
            Config.jimmypwn_llms = Config.jimmypwn_llms_opus_first

        # Set the jimmy pwn model index based on the configuration
        # NOTE: jimmyPwn always starts with claude-4-sonnet
        # NOTE: opus is only used a MAX of Config.max_opus_for_jimmypwn times
        #       every sink check will be done first with claude-4-sonnet.
        jimmy_pwn_llm_index = 0
        jimmy_pwn_model = Config.jimmypwn_llms[jimmy_pwn_llm_index]
        jimmyPwn.__LLM_MODEL__ = jimmy_pwn_model
        jimmyPwn.llm  = jimmyPwn.get_llm_by_name(
                                                 jimmy_pwn_model,
                                                 **jimmyPwn.__LLM_ARGS__,
                                                 raise_on_budget_exception=jimmyPwn.__RAISE_ON_BUDGET_EXCEPTION__,
                                                 raise_on_rate_limit_exception=jimmyPwn.__RAISE_ON_RATE_LIMIT_EXCEPTION__
                                                 )

        if jimmyPwn.__LLM_MODEL__ == "claude-4-opus":
            logger.info(f'🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥')
            logger.info(f"Starting jimmyPwn with {jimmyPwn.__LLM_MODEL__} model...")
            logger.info(f'🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥')
        else:
            logger.info(f"Starting jimmyPwn with {jimmyPwn.__LLM_MODEL__} model...")

        ########################################################
        # 🧠🔄 jimmyPwn will reason and see how to exploit the bug
        while True:
            try:
                res = jimmyPwn.invoke()
                JimmyPwnAnalysisReport = res.value
                if res.value:
                    self.lastest_analysis_report = JimmyPwnAnalysisReport
                self.how_many_naps = 0
                # 🧠🔄⛓️‍💥
                break
            except LLMApiBudgetExceededError as e:
                logger.critical(f' 😭 LLM API budget exceeded for {jimmyPwn.__LLM_MODEL__}!')
                # NOTE: WE DO NOT SWITCH MODEL HERE, DISCOVERY GUY MODELS MUST BE FROM ANTHROPIC!
                # NOTE: Budget is PER-PROVIDER, therefore we cannot switch model here, but we just wait.
                if Config.nap_mode == True and self.how_many_naps < Config.nap_becomes_death_after:
                    self.how_many_naps += 1
                    logger.info(f'😴 Taking nap number {self.how_many_naps}...')
                    self.take_a_nap()
                    # 🧠🔄▶️
                    continue
                else:
                    total_cost = agentlib.lib.agents.agent.global_event_dumper.total_cost_per_million / 1_000_000
                    logger.info(f' 💸 Total cost of the failing discoveryguy process: {total_cost}\n')
                    # 🧠🔄⛓️‍💥
                    self.exit_and_clean(1)
            except LLMApiRateLimitError as e:
                # NOTE: RATE-LIMIT is per model, let's move to the next model.
                logger.critical(f' 😭 LLM API rate limit exceeded for {jimmyPwn.__LLM_MODEL__}!')
                jimmy_pwn_llm_index += 1

                try:
                    if jimmy_pwn_llm_index >= len(Config.jimmypwn_llms):
                        # All right, we tried all the models, we cannot continue.
                        # Reset to the first model and then we nap
                        jimmy_pwn_llm_index = 0

                        # Brain surgery for JimmyPwn 🧠🔬
                        jimmy_pwn_model = Config.jimmypwn_llms[jimmy_pwn_llm_index]
                        jimmyPwn.__LLM_MODEL__ = jimmy_pwn_model
                        jimmyPwn.llm  = jimmyPwn.get_llm_by_name(
                                                                 jimmy_pwn_model,
                                                                 **jimmyPwn.__LLM_ARGS__,
                                                                 raise_on_budget_exception=jimmyPwn.__RAISE_ON_BUDGET_EXCEPTION__,
                                                                 raise_on_rate_limit_exception=jimmyPwn.__RAISE_ON_RATE_LIMIT_EXCEPTION__
                                                                 )

                        if Config.nap_mode == True and self.how_many_naps < Config.nap_becomes_death_after:
                            self.how_many_naps += 1
                            logger.info(f'😴 Taking nap number {self.how_many_naps}...')
                            self.take_a_nap()
                            # 🧠🔄▶️
                            continue
                        else:
                            total_cost = agentlib.lib.agents.agent.global_event_dumper.total_cost_per_million / 1_000_000
                            logger.info(f' 💸 Total cost of the failing discoveryguy process: {total_cost}\n')
                            # 🧠🔄⛓️‍💥
                            self.exit_and_clean(1)
                    else:
                        # We switch to the next model and try again
                        jimmy_pwn_model = Config.jimmypwn_llms[jimmy_pwn_llm_index]
                        logger.info(f' 🧠🔄 Switching to {jimmy_pwn_model} model...')

                        # Managing opus a bit more carefully.
                        if jimmy_pwn_model == "claude-4-opus":
                            # NOTE: if we are switching to opus we need to
                            # be a bit more conservative (expensive!)
                            if self.how_many_opus >= Config.max_opus_for_jimmypwn:
                                # Reset the index to the first model
                                jimmy_pwn_llm_index = 0
                                # Remove opus from discoveryguy...sad.
                                Config.jimmypwn_llms = Config.jimmypwn_llms_no_opus
                                # Well, now we have to wait since we got rate limited.
                                self.how_many_naps += 1
                                logger.info(f'😴 Taking nap number {self.how_many_naps}...')
                                self.take_a_nap()
                                # 🧠🔄▶️
                                continue
                            else:
                                self.how_many_opus += 1
                                logger.info(f'🦸🏻‍♂️🦸🏻‍♂️🦸🏻‍♂️ Jimmypwn UPGRADE! Switching to {jimmy_pwn_model} 🦸🏻‍♂️🦸🏻‍♂️🦸🏻‍♂️')

                        # Brain surgery for JimmyPwn 🧠🔬
                        jimmyPwn.__LLM_MODEL__ = Config.jimmypwn_llms[jimmy_pwn_llm_index]
                        jimmyPwn.llm  = jimmyPwn.get_llm_by_name(
                                                                 jimmy_pwn_model,
                                                                 **jimmyPwn.__LLM_ARGS__,
                                                                 raise_on_budget_exception=jimmyPwn.__RAISE_ON_BUDGET_EXCEPTION__,
                                                                 raise_on_rate_limit_exception=jimmyPwn.__RAISE_ON_RATE_LIMIT_EXCEPTION__
                                                                 )

                        # 🧠🔄▶️
                        continue
                except Exception as e:
                    logger.error(f" 😭 Error while doing brain surgery on jimmyPwn: {e}")
                    # 🧠🔄⛓️‍💥
                    return False, feedback_for_jimmy_pwn, True

            except LLMApiContextWindowExceededError as e:
                logger.critical(f' 😭 LLM API context window exceeded for {jimmyPwn.__LLM_MODEL__}!')
                # 🧠🔄⛓️‍💥
                return False, feedback_for_jimmy_pwn, True
            except Exception as e:
                # NOTE: this is a generic error, we just log it and retry.
                #  For exampe: the context window is exceeded,
                logger.error(f" 😭 Unknown Error in jimmyPwn.invoke(): {e}")
                logger.error("Retrying...")
                # 🧠🔄⛓️‍💥
                return False, feedback_for_jimmy_pwn, True

        # 🧠🔄
        ##########################################################

        # NOTE: check on why we stop
        try:
            if res.chat_messages[-1].response_metadata:
                stop_reason = res.chat_messages[-1].response_metadata["finish_reason"]
            else:
                stop_reason = "max_chats"

        except Exception as e:
            logger.error("Error getting finish reason from response metadata, assuming 'unknown'.", e)
            stop_reason = "unknown"

        if stop_reason == "length":
            logger.warning("Analysis report is too long, truncating it to fit the context window.")
            try:
                if "</" in JimmyPwnAnalysisReport:
                    JimmyPwnAnalysisReport = "</".join(JimmyPwnAnalysisReport.split("</")[:-1])
                else:
                    JimmyPwnAnalysisReport = res.value[:Config.max_analysis_report_length]
            except Exception as e:
                logger.error(f"Error truncating analysis report: {e}")
                if self.lastest_analysis_report != "":
                    logger.info("Using the last analysis report instead.")
                    JimmyPwnAnalysisReport = self.lastest_analysis_report
                else:
                    return False, "The format of the analysis report in the last run was poor; please note the output format of the report!", False
        elif stop_reason == "max_chats":
            logger.warning("Max chats reached, using the last analysis report.")
            if self.lastest_analysis_report != "":
                JimmyPwnAnalysisReport = self.lastest_analysis_report
            else:
                feedback_for_jimmy_pwn = "\nIn the last run, you invoked the tool too many times. Please try again later. The max number of tool call is 70.\n"
                return False, feedback_for_jimmy_pwn, False
        else:
            logger.warning(f"Unknown stop reason: {stop_reason}, using the last analysis report.")
        # NOTE: The seed generation model is the agent that is in charge of
        #       developing the Python script.
        # 🌱
        seedAgent = SeedGenerationModel(
            LANGUAGE_EXPERTISE=self.project_language,
            HARNESSES=list(reached_harnesses.values()),
            SINK_FUNCTION=self.func_resolver.get_code(sink_index_key)[-1],
            REPORT=JimmyPwnAnalysisReport,
            FEEDBACK=feedback_for_seed_agent,
            BAD_SCRIPTS=bad_scripts,
            FAILED_SCRIPTS=failed_scripts,
            FIRST_ATTEMPT=True
        )

        #####################################################
        # 🐍👨🏻‍💻🔄 Develop the script feedback loop.
        #####################################################
        seed_attempt_no = 0
        while seed_attempt_no < Config.exploit_dev_max_attempts_regenerate_script:
            if seed_attempt_no > 0:
                seedAgent.FIRST_ATTEMPT = False
            # This will do another invocation of the seedAgent
            try:
                found_good_crash, found_unintended_crash, feedback, sandbox_report, exploit_script, crash_txt = self.run_seed_generation(seedAgent, reached_harnesses, sink_index_key, report_attempt_no, seed_attempt_no)
            except Exception as e:
                logger.error(f'[CRITICAL] ☠️ Error during run_seed_generation: {e}')
                return found_good_crash, feedback_for_jimmy_pwn, False

            if found_good_crash:
                # We are done!
                logger.info(f"🔥🏆 We got a crash for the function {sink_index_key} with input {crash_txt} in report attempt {report_attempt_no+1}, seed attempt {seed_attempt_no+1}!")
                #🐍👨🏻‍💻⛓️‍💥
                return found_good_crash, feedback_for_jimmy_pwn, False
            elif found_unintended_crash:
                logger.info(f"🔥🤷🏻‍♂️ We got a crash for the function {sink_index_key} with input {crash_txt} in report attempt {report_attempt_no+1}, seed attempt {seed_attempt_no+1}, but the sink function was not covered, trying again...")
                feedback_for_jimmy_pwn += feedback
                feedback_for_seed_agent += feedback
                bad_scripts.append(exploit_script)
                #🐍👨🏻‍💻⛓️‍💥
                return found_good_crash, feedback_for_jimmy_pwn, False
            else:
                logger.info(f"Report attempt {report_attempt_no+1} , seed attempt {seed_attempt_no+1} failed, trying again...")
                failed_scripts.append(exploit_script)
                feedback_for_seed_agent += feedback
                seedAgent.FEEDBACK = feedback_for_seed_agent
                seed_attempt_no += 1
                #🐍👨🏻‍💻▶️
                #########################################################

        #####################################################
        # 🐍👨🏻‍💻🔄
        #####################################################

        # NOTE: we failed to generate a valid seed that crash the challenge with the current scripts.
        return found_good_crash, feedback_for_jimmy_pwn, False

    def emit_sarif_assesment(self, verdict, summary):
        # NOTE: the report should be written into the sarif_retry_metadatas
        sarif_metadata_output = SARIFMetadata(
            task_id=self.sarif_meta.task_id,
            sarif_id=self.sarif_meta.sarif_id,
            pdt_sarif_id=self.sarif_meta.pdt_sarif_id,
            pdt_task_id=self.sarif_meta.pdt_task_id,
            metadata=self.sarif_meta.metadata,
            assessment=Assessment.AssessmentCorrect if verdict == "TP" else Assessment.AssessmentIncorrect,
            description=summary,
        )

        # Write the dictionary as yaml into the output path
        with open(self.sarif_assessment_out_path, 'w') as f:
            f.write(sarif_metadata_output.model_dump_json(indent=2))

        logger.info(f" 📑 Emitting assessment report to {self.sarif_assessment_out_path}")

    def exit_and_clean(self, code):
        # Wipe self.oss_fuzz_debug_targets_folder
        try:
            # if this is not a local run
            if not Config.is_local_run:
                if os.path.exists(self.oss_fuzz_debug_targets_folder):

                    # Sanitize the folder name as much as we can to avoid wipe other stuff!
                    # =====================================================================

                    try:
                        # Resolve and normalize the path
                        normalized_path = os.path.realpath(self.oss_fuzz_debug_targets_folder)
                        canonical_path = os.path.normpath(normalized_path)
                    except (OSError, ValueError) as e:
                        logger.error(f"🧼🥴 Invalid path: {e}")
                        exit(code)

                    # Ensure the resolved path is still within the allowed directory
                    allowed_prefix = os.path.realpath("/shared/discoveryguy/")
                    if not canonical_path.startswith(allowed_prefix + os.sep):
                        logger.error(f"🧼🥴 Path {canonical_path} is outside allowed directory")
                        exit(code)

                    # Additional safety: ensure it's a directory, not a file or special device
                    if not os.path.isdir(canonical_path):
                        logger.error(f"🧼🥴 Path {canonical_path} is not a directory")
                        exit(code)

                    if canonical_path == None or canonical_path == "":
                        logger.error(f" 🧼🥴 The oss_fuzz_debug_targets_folder {canonical_path} is not a valid path, skipping cleanup.")
                        exit(code)
                    if canonical_path == "/shared/" or canonical_path == "/shared":
                        logger.error(f" 🧼🥴 The oss_fuzz_debug_targets_folder {canonical_path} is not a valid path, skipping cleanup.")
                        exit(code)
                    if canonical_path == "/shared/discoveryguy":
                        logger.error(f" 🧼🥴 The oss_fuzz_debug_targets_folder {canonical_path} is not a valid path, skipping cleanup.")
                        exit(code)
                    if canonical_path == "/shared/discoveryguy/":
                        logger.error(f" 🧼🥴 The oss_fuzz_debug_targets_folder {canonical_path} is not a valid path, skipping cleanup.")
                        exit(code)
                    if "*" in canonical_path:
                        logger.error(f" 🧼🥴 The oss_fuzz_debug_targets_folder {canonical_path} is not a valid path, skipping cleanup.")
                        exit(code)
                    if not canonical_path.startswith("/shared/discoveryguy/"):
                        logger.error(f" 🧼🥴 The oss_fuzz_debug_targets_folder {canonical_path} is not a valid path, skipping cleanup.")
                        exit(code)
                    if ".." in canonical_path:
                        logger.error(f" 🧼🥴 The oss_fuzz_debug_targets_folder {canonical_path} is not a valid path, skipping cleanup.")
                        exit(code)
                    # =====================================================================

                    # ⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️
                    shutil.rmtree(canonical_path)
                    # ⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️

                    logger.info(f"🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧")
                    logger.info(f" 🧼 Cleaned up the oss_fuzz_debug_targets folder: {canonical_path} 🧼")
                    logger.info(f"🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧🫧")

        except Exception as e:
            logger.error(f" 🧼🥴 Failed to clean up the oss_fuzz_debug_targets folder: {e}")

        # 👋🏼
        exit(code)

    def get_diff_summary_from_agent(self, diff_content):
        curr_llm_index = 0

        summaryAgent = SummaryAgent(
            LANGUAGE_EXPERTISE=self.project_language,
            PROJECT_NAME=self.project_name,
            DIFF=diff_content
        )

        # Set the first model to the SummaryAgent
        summary_agent_model = Config.summary_agent_llms[curr_llm_index]
        summaryAgent.__LLM_MODEL__ = summary_agent_model
        summaryAgent.llm  = summaryAgent.get_llm_by_name(
                                                         summary_agent_model,
                                                         **summaryAgent.__LLM_ARGS__,
                                                         raise_on_budget_exception=summaryAgent.__RAISE_ON_BUDGET_EXCEPTION__,
                                                         raise_on_rate_limit_exception=summaryAgent.__RAISE_ON_RATE_LIMIT_EXCEPTION__
                                                         )

        ########################################################################
        # 🧠🔄
        while True:
            try:
                logger.info(" 🚰 Using SummaryAgent to summarize the diff file...")
                summary = summaryAgent.invoke().value

                self.how_many_naps = 0
                logger.info(f" 🚰 We got a Diff file Summary.")
                logger.info(f" 🚰 Diff file summary: {summary}")

                # 🧠🔄⛓️‍💥⬆️
                return summary

            except (LLMApiBudgetExceededError, LLMApiRateLimitError) as e:

                logger.critical(f' 😭 Exception {e} during execution of {summaryAgent.__LLM_MODEL__}!')
                curr_llm_index += 1

                if curr_llm_index >= len(Config.summary_agent_llms):
                    logger.info(f' 😶‍🌫️ No more LLMs to try. SummaryGuy goes to sleep!')

                    # Reset the LLM index
                    curr_llm_index = 0

                    if Config.nap_mode == True and self.how_many_naps < Config.nap_becomes_death_after:
                        self.how_many_naps += 1
                        logger.info(f'😴 Taking nap number {self.how_many_naps}...')
                        self.take_a_nap()
                        logger.info(f'🫡 Nap time is over! Back to work...')

                        # Brain surgery for summaryAgent 🧠🔬
                        summary_agent_model = Config.summary_agent_llms[curr_llm_index]
                        logger.info(f' 🧠🔄 Switching to {summary_agent_model} model...')
                        summaryAgent.__LLM_MODEL__ = summary_agent_model
                        summaryAgent.llm  = summaryAgent.get_llm_by_name(
                                                                         summary_agent_model,
                                                                         **summaryAgent.__LLM_ARGS__,
                                                                         raise_on_budget_exception=summaryAgent.__RAISE_ON_BUDGET_EXCEPTION__,
                                                                         raise_on_rate_limit_exception=summaryAgent.__RAISE_ON_RATE_LIMIT_EXCEPTION__
                                                                         )

                        # 🧠🔄▶️
                        continue
                    else:
                        total_cost = agentlib.lib.agents.agent.global_event_dumper.total_cost_per_million / 1_000_000
                        logger.info(f' 💸 Total cost of the failing discoguy process: {total_cost}\n')

                        # 🧠🔄⛓️‍💥⬆️
                        self.exit_and_clean(1)
                else:
                    # We switch to the next model and try again
                    summary_agent_model = Config.summary_agent_llms[curr_llm_index]
                    logger.info(f' 🧠🔄 Switching to {summary_agent_model} model...')
                    summaryAgent.__LLM_MODEL__ = summary_agent_model
                    summaryAgent.llm  = summaryAgent.get_llm_by_name(
                                                                     summary_agent_model,
                                                                     **summaryAgent.__LLM_ARGS__,
                                                                     raise_on_budget_exception=summaryAgent.__RAISE_ON_BUDGET_EXCEPTION__,
                                                                     raise_on_rate_limit_exception=summaryAgent.__RAISE_ON_RATE_LIMIT_EXCEPTION__
                                                                     )

                    # 🧠🔄▶️
                    continue

            except Exception as e:
                logger.error(f" 🚰 Error while running SummaryAgent: {e}")
                logger.info(" 🚰 Diff file is too large, skipping SummaryAgent.")
                # 🧠🔄⛓️‍💥⬆️
                summary = ""
                return summary
        # 🧠🔄
        ########################################################################

    def get_harnesses_in_scope_with_agent(self, sink_index_key, sink_funcname, sink_full_info, all_harnesses):
        curr_llm_index = 0
        reached_harnesses = {}

        try:
            # 🍯
            harnessAgent = HoneySelectAgent(
                    LANGUAGE_EXPERTISE=self.project_language,
                    PROJECT_NAME=self.project_name,
                    FUNCTION_INDEX= sink_index_key,
                    FUNCTION_NAME=sink_funcname,
                    FILE_NAME=str(sink_full_info.target_container_path),
                    CODE=self.func_resolver.get_code(sink_index_key)[-1],
                    HARNESSES=list(all_harnesses.values()),
            )

            # Set the first model to the HoneySelectAgent
            honey_agent_model = Config.honey_select_llms[curr_llm_index]
            harnessAgent.__LLM_MODEL__ = honey_agent_model
            harnessAgent.llm  = harnessAgent.get_llm_by_name(
                                                             honey_agent_model,
                                                             **harnessAgent.__LLM_ARGS__,
                                                             raise_on_budget_exception=harnessAgent.__RAISE_ON_BUDGET_EXCEPTION__,
                                                             raise_on_rate_limit_exception=harnessAgent.__RAISE_ON_RATE_LIMIT_EXCEPTION__
                                                            )

            # 🧠🔄
            ############################################################
            while True:
                try:
                    harnesslist = harnessAgent.invoke().value
                    self.how_many_naps = 0
                    # Get all the harnesses in scope according to the agent.
                    for h in harnesslist:
                        reached_harnesses[h] = all_harnesses[h]

                    # 🧠🔄⛓️‍💥⬆️
                    return reached_harnesses

                except (LLMApiBudgetExceededError, LLMApiRateLimitError) as e:

                    logger.critical(f' 😭 HoneySelect Exception {e} during execution of {harnessAgent.__LLM_MODEL__}!')
                    curr_llm_index += 1

                    if curr_llm_index >= len(Config.honey_select_llms):
                        logger.info(f' 😶‍🌫️ No more LLMs to try. HoneySelect goes to sleep!')

                        # Reset the LLM index
                        curr_llm_index = 0

                        if Config.nap_mode == True and self.how_many_naps < Config.nap_becomes_death_after:
                            self.how_many_naps += 1
                            logger.info(f'😴 Taking nap number {self.how_many_naps}...')
                            self.take_a_nap()
                            logger.info(f'🫡 Nap time is over! Back to work...')

                            # Brain surgery for agent 🧠🔬
                            honey_agent_model = Config.honey_select_llms[curr_llm_index]
                            logger.info(f' 🧠🔄 HoneySelect Switching to {honey_agent_model} model...')
                            harnessAgent.__LLM_MODEL__ = honey_agent_model
                            harnessAgent.llm  = harnessAgent.get_llm_by_name(
                                                                             honey_agent_model,
                                                                             **harnessAgent.__LLM_ARGS__,
                                                                             raise_on_budget_exception=harnessAgent.__RAISE_ON_BUDGET_EXCEPTION__,
                                                                             raise_on_rate_limit_exception=harnessAgent.__RAISE_ON_RATE_LIMIT_EXCEPTION__
                                                                             )

                            # 🧠🔄▶️
                            continue
                        else:
                            total_cost = agentlib.lib.agents.agent.global_event_dumper.total_cost_per_million / 1_000_000
                            logger.info(f' 💸 Total cost of the failing discoguy process: {total_cost}\n')

                            # 🧠🔄⛓️‍💥⬆️
                            self.exit_and_clean(1)
                    else:
                        # We switch to the next model and try again
                        honey_agent_model = Config.honey_select_llms[curr_llm_index]
                        logger.info(f' 🧠🔄 Switching to {honey_agent_model} model...')
                        harnessAgent.__LLM_MODEL__ = honey_agent_model
                        harnessAgent.llm  = harnessAgent.get_llm_by_name(
                                                                         honey_agent_model,
                                                                         **harnessAgent.__LLM_ARGS__,
                                                                         raise_on_budget_exception=harnessAgent.__RAISE_ON_BUDGET_EXCEPTION__,
                                                                         raise_on_rate_limit_exception=harnessAgent.__RAISE_ON_RATE_LIMIT_EXCEPTION__
                                                                         )

                        # 🧠🔄▶️
                        continue

                except Exception as e:
                    logger.error(f"Error while running HoneySelectAgent: {e}")
                    reached_harnesses = {k: all_harnesses[k] for k in list(all_harnesses)[:5]}
                    # 🧠🔄⛓️‍💥⬆️
                    return reached_harnesses
            # 🧠🔄
            ############################################################

        except Exception as e:
            logger.error(f"Error while running HoneySelectAgent: {e}. YOLOing using the first 5 harnesses!")
            reached_harnesses = {k: all_harnesses[k] for k in list(all_harnesses)[:5]}

        return reached_harnesses

    def start(self):
        #####################################################
        # 🚰 First we are getting the sinks based on the mode
        #####################################################
        if Config.discoveryguy_mode == DiscoverGuyMode.SARIF:
            sarif_tg_summary, all_sinks = self.get_sarif_triage_summary()
        elif Config.discoveryguy_mode == DiscoverGuyMode.POISBACKDOOR:
            all_sinks:List[FUNCTION_INDEX_KEY] = self.get_suspicious_funcs()
        elif Config.discoveryguy_mode == DiscoverGuyMode.POIS:
            # These are the ranked functions as per code-swipe
            all_sinks:List[FUNCTION_INDEX_KEY] = self.get_ranked_functions()
        elif Config.discoveryguy_mode == DiscoverGuyMode.DIFFONLY:
            all_sinks:List[FUNCTION_INDEX_KEY] = self.get_sinks_from_diff()
        else:
            logger.critical(" ❌ Invalid DiscoveryGuy mode! ")
            self.exit_and_clean(1)

        # Do we have 🚰 at all?
        if len(all_sinks) == 0:
            logger.info(' 🚰🤷🏻‍♂️ No sinks found, bye!')
            self.exit_and_clean(0)
        else:
            logger.info(f' DiscoveryGuy is going to check {min(len(all_sinks),Config.max_pois_to_check)} out of {len(all_sinks)} POIs')

        ## DIFF file summary
        summary = ""
        if Config.crs_mode == CRSMode.DELTA:
            with open(self.diff_file, 'r') as f:
                diff_content = f.read()

            # We are gonna use the agent only if the diff has a max size.
            if len(diff_content.splitlines()) < Config.max_diff_lines_for_summary:
                summary = self.get_diff_summary_from_agent(diff_content)
            else:
                # If the diff file is too large, we skip the summary.
                logger.info(" 🚰 Diff file is too large, skipping SummaryAgent.")
        else:
            logger.info(" 🚰 CRS mode is not DELTA, skipping SummaryAgent.")
            summary = ""


        # 🚰🔬🔄 Check the sinks
        #####################################################
        checked_sinks = 0
        for sink_num, sink_index_key in enumerate(all_sinks):

            logger.info(f"================================================================")
            logger.info(f"[{sink_num+1}/{len(all_sinks)}] Processing POI: {sink_index_key}")
            logger.info(f"================================================================")

            # If we want to check the top N sinks with opus first, we change the
            # jimmypwn_llms to the opus first list.
            # 🦸🏻‍♂️?
            if Config.check_top_n_with_opus:
                # If we are still under the max opus for jimmypwn, we
                # keep using opus first to check the first N warnings.
                if checked_sinks < Config.max_opus_for_jimmypwn:
                    # 🦸🏻‍♂️▶️
                    Config.jimmypwn_llms = Config.jimmypwn_llms_opus_first
                else:
                    # In case we check all the top N sinks with opus, we switch to the second opus list
                    # 👋🏼📖🦸🏻‍♂️
                    Config.check_top_n_with_opus = False
                    Config.jimmypwn_llms = Config.jimmypwn_llms_opus_second

            sink_full_info:FunctionIndex = self.func_resolver.get(sink_index_key)
            sink_funcname:str = self.func_resolver.get_funcname(sink_index_key)

            if Config.skip_already_pwned and Config.discoveryguy_mode != DiscoverGuyMode.SARIF:
                # NOTE: for SARIF, we would still like to try to genereate a seed given the precise
                #       information in the report (we also are gonna create the link here!)
                try:
                    if len(self.analysis_graph_api.is_sink_crashed_already(sink_funcname)) != 0:
                        logger.info(f" 🚰💥✅ POI {sink_index_key} is already crashed! skipping...")
                        continue
                except Exception as e:
                    logger.warning(f"Error while checking for existing crashes for sink {sink_index_key}: {e}. Skipping this check...")

            if sink_full_info is None:
                # NOTE: something terribly broken?
                logger.info(f" 🚮 POI {sink_full_info} not found in the function index, skipping...")
                continue

            checked_sinks += 1

            # NOTE: Here is fine to use the function_index_key because we are looking for a
            #       static path from the harness to the sink (without using coverage data)
            with_path:bool = False
            # NOTE: A good crash is a crash that contains the sink function, everything else
            #       is considered unintended.
            found_good_crash:bool = False
            # NOTE: we are gonna store here all the harnesses in scope for this sink
            reached_harnesses:dict = {}
            # NOTE: the prefix is the harness prefix function (depends on the language)
            prefix:str = self.harness_resolver.get_harness_prefix_in_scope()
            # NOTE: this is returning all the HarnessesNode in scope (i.e., do we find a path?)
            try:
                harnesses_in_scope:List = self.analysis_graph_api.check_exists_path_to_harness(prefix, sink_index_key)
            except Exception as e:
                logger.error(f"Error while checking path to harness for sink {sink_index_key}: {e}")
                harnesses_in_scope = []

            if len(harnesses_in_scope) == 0:
                # NOTE: If we cannot find a path from harness to sink in analysis graph we try all the harnesses.
                logger.info(f" 🚰😶‍🌫️ No harnesses can reach this sink {sink_index_key}")
                with_path = False
            else:
                logger.info(f" 🚰👍 {len(harnesses_in_scope)} harnesses can reach this sink {sink_index_key}")
                with_path = True

            all_harnesses = {}
            for harness in self.harness_resolver.get_all_harnesses():
                all_harnesses[harness.func_key] = harness

            if len(all_harnesses) > 5:
                reached_harnesses = self.get_harnesses_in_scope_with_agent(sink_index_key, sink_funcname, sink_full_info, all_harnesses)
                logger.info(f" 🚰🎯 Using {len(reached_harnesses)} harnesses: {reached_harnesses}")
            else:
                # NOTE: If we have less than 5 harnesses, we just use all of them
                reached_harnesses = all_harnesses
                logger.info(f" There are less than 5 harnesses so we using all of them: {reached_harnesses}")
                logger.info(f" 🚰🎯 Using {len(reached_harnesses)} harnesses: {reached_harnesses}")

            # Graph simplification!
            nodes = self.path_simplifier.get_nodes(reached_harnesses, sink_index_key, with_path=with_path)

            ######################################################################
            # MAIN EXPLOIT GENERATION ATTEMPT STARTS
            # 🚰☠️🔄
            ######################################################################
            attempt_no = 0
            notice = ""
            feedback = ""
            try:
                self.fuzz_request[sink_index_key] = {
                    "seeds": []
                }
            except Exception as e:
                print("GO GO GO!!!!!!")
            while attempt_no <= Config.exploit_dev_max_attempts_per_sink:
                if attempt_no ==0:
                    self.lastest_analysis_report = ""

                # benign_seed_template, closest_func = self.get_closest_benign_seed_to_sink(nodes)
                # benign_seed_template, closest_func = self.get_closest_benign_seed_to_sink(nodes)
                # 🧙🏻‍♂️🥟⚔️🍕🧙🏻‍♂️
                jimmyPwn = JimmyPwn(
                    LANGUAGE_EXPERTISE=self.project_language,
                    PROJECT_NAME=self.project_name,
                    FUNCTION_INDEX= sink_index_key,
                    FUNCTION_NAME=sink_funcname,
                    FILE_NAME=str(sink_full_info.target_container_path),
                    CODE=self.func_resolver.get_code(sink_index_key)[-1],
                    CODE_DIFF = self.peek_diff.get_diff(sink_index_key, bot=False) if self.peek_diff else "",
                    WITH_PATH=with_path,
                    HARNESSES=list(reached_harnesses.values()),
                    NODES_OPTIMIZED=nodes,
                    NOTICE=notice,
                    FEEDBACK = feedback,
                    WITH_DIFF=True if self.peek_diff else False,
                    LAST_CHANCE=True if attempt_no > 1 else False,
                    DIFF_SUMMARY=summary,
                    # WITH_BENIGN_TEMPLATE=benign_seed_template,
                    # LAST_BENIGN_FUNC_REACHED=closest_func,
                    # WITH_BENIGN_TEMPLATE=benign_seed_template,
                    # LAST_BENIGN_FUNC_REACHED=closest_func,
                )

                if Config.discoveryguy_mode == DiscoverGuyMode.SARIF:
                    # NOTE: add the sarif summary if we are in SARIF mode
                    jimmyPwn.add_sarif_summary(sarif_tg_summary)

                # NOTE: Always remember to clean the call history cache every
                #       time we instantiate a new agent that uses the toolbox
                self.peek_src.clean_tool_call_history()

                script_input = str(self.sandbox.artifacts_dir_work)

                logger.info("🪄 ===Starting exploit development attempts=== 🪄")

                # NOTE: this is calling the exploitDev.invoke()
                found_good_crash, feedback, error  = self.run_exploit_dev(jimmyPwn, reached_harnesses, sink_index_key, attempt_no)

                if error:
                    logger.error("Error while running exploit development, skipping to the next sink.")
                    break

                if found_good_crash:

                    if Config.discoveryguy_mode == DiscoverGuyMode.SARIF:
                        # NOTE: if we are in SARIF mode, we want to emit the assessment at this point.
                        res = jimmyPwn.set_human_msg("You succeed! Now generate an executive summary on why this SARIF report was actually a true positive and how you managed to exploit the vulnerability reported in it.")
                        summary = '-'

                        # Attempt to generate a summary. If we fail we just give up.
                        try:
                            res = jimmyPwn.invoke()
                            summary = res.chat_messages[-1].content
                        except Exception as e:
                            logger.error(f"Error while generating summary: {e}")

                        # Emit the sarif assessment
                        self.emit_sarif_assesment("TP", summary)

                    # 🚰☠️⛓️‍💥 This terminates attempting exploiting this sink
                    # 🚰🔬▶️ This will go to the next sink
                    break
                else:
                    # TODO-JIMMY: why we are setting the feedback to empty here!?
                    jimmyPwn.FEEDBACK = ""

                attempt_no += 1
            ######################################################################
            # 🚰☠️🔄
            ######################################################################
            if Config.send_fuzz_request and not found_good_crash:
                try:
                    """
                        project_id: "ed7f44792f4ae1c74a0fab0b13714899"
                        build_configuration_id: "ed7f44792f4ae1c74a0fab0b13714899"
                        harnesses_in_scope:
                          - "TestFuzzCodecs"
                          - "TestFuzzCoreServer"
                          - "TestFuzzCoreClient"
                        seed_hashes:
                          - "a1b2c3d4e5f6789012345678901234567890abcd"
                          - "fedcba0987654321098765432109876543210fedcb"
                          - "1234567890abcdef1234567890abcdef12345678"
                    """
                    build_configurations = self.aggregated_harness_info['build_configurations']
                    build_configuration_id = None
                    for k, v in build_configurations.items():
                        if v['sanitizer'] == 'address':
                            build_configuration_id = k
                            break
                    if build_configuration_id is None:
                        raise ValueError("No build configuration found with address sanitizer")
                    # now lets dump the yaml
                    harnesses_in_scope = [harness.bin_name for harness in reached_harnesses.values()]
                    seed_hashes = self.fuzz_request[sink_index_key]['seeds']
                    fuzz_request = {
                        'project_id': self.project_id,
                        'build_configuration_id': build_configuration_id,
                        'harnesses_in_scope': harnesses_in_scope,
                        'seed_hashes': seed_hashes,
                        'fuzz_payload': "NO",
                        'harness_payload': "NO"
                    }
                    if self.fuzz_payload is not None:
                        fuzz_request['fuzz_payload'] = self.fuzz_payload
                        harness_info_dump = ""
                        for harn_id, harn_data in self.aggregated_harness_info['harness_infos'].items():
                            harness_info_dump += f"{harn_id}:{str(harn_data)}\n"
                        harness_payload = base64.b64encode(harness_info_dump.encode()).decode()
                        fuzz_request['harness_payload'] = harness_payload
                    fuzz_request_yaml = yaml.dump(fuzz_request, default_flow_style=False)
                    disco_request_dir = os.environ.get("DISCO_FUZZ_REQUEST", None)
                    if disco_request_dir is None:
                        raise ValueError("DISCO_FUZZ_REQUEST environment variable is not set")
                    fuzz_request_uuid = hashlib.md5(fuzz_request_yaml.encode()).hexdigest()
                    disco_request_path = Path(disco_request_dir) / f"{fuzz_request_uuid}.yaml"
                    # Write the fuzz request to the file
                    with open(disco_request_path, 'w') as f:
                        f.write(fuzz_request_yaml)
                    logger.info(f" 🚰 Fuzz request written to {disco_request_path}")

                except Exception as e:
                    print("Failed to emit build fuzz request")
                    print("Go Go Go !!!!!!!!!!!!!!!!!!!!")
                    continue

        logger.info(f'Done checking all the sinks! 🚰✅')
        self.exit_and_clean(0)

        #####################################################
        # 🚰🔬🔄
        #####################################################
'''
________  .__                                               ________
\______ \ |__| ______ ____  _______  __ ___________ ___.__./  _____/ __ __ ___.__.
 |    |  \|  |/  ___// ___\/  _ \  \/ // __ \_  __ <   |  /   \  ___|  |  <   |  |
 |    `   \  |\___ \\  \__(  <_> )   /\  ___/|  | \/\___  \    \_\  \  |  /\___  |
/_______  /__/____  >\___  >____/ \_/  \___  >__|   / ____|\______  /____/ / ____|
        \/        \/     \/                \/       \/            \/       \/
'''
def main(**kwargs):
    discoveryGuy = DiscoveryGuy(**kwargs)
    discoveryGuy.start()
