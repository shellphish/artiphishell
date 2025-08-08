
import agentlib
import logging
import os
import hashlib

from datetime import datetime

from .patch_generator import PatchGenerator
from .utils import RootCauseGenerator, Programmer
from .toolbox import PeekSrcSkill, PeekLogsSkill, PeekDiffSkill

from .helper import Helper
from .config import Config
from .models import FailedPatch, MitigatedPovReport, CrashingInput

from shellphish_crs_utils.pydatatask import PDTRepo
from shellphish_crs_utils.models.crs_reports import PoVReport

from patcherq.config import Config, PatcherqMode, CRSMode

logging.getLogger('shellphish_crs_utils.challenge_project').setLevel(logging.WARNING)
logging.getLogger('shellphish_crs_utils.oss_fuzz.target_runner_service').setLevel(logging.WARNING)
logging.getLogger('analysis_graph.models').setLevel(logging.WARNING)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logging.getLogger("httpx").setLevel(logging.WARNING)

class PatcherQ:
    def __init__(self, **kwargs):
        self.kwargs = kwargs

        if Config.patcherq_mode == PatcherqMode.SARIF:
            # If we are patching from SARIF, we are not generating a new SARIF.
            Config.generate_sarif = False
            self.sarif_report_id = kwargs['sarif_id']

        elif Config.patcherq_mode == PatcherqMode.REFINE:
            self.failing_patch = kwargs['failing_patch']
            self.failed_functionality = kwargs['failed_functionality']
            
        self.crashing_inputs_to_test = kwargs['crashing_inputs_to_test']
        
        # Create the PDT repo where we will emit the artifacts
        if Config.emit_patched_artifacts:
            self.patched_artifacts_out = PDTRepo(
                                                kwargs['patched_artifacts_dir'], 
                                                kwargs['patched_artifacts_dir_lock']
                                                )

        # Extract project info
        self.project_name, self.project_language = Helper.get_project_info(self.kwargs['project_yaml'])

        # Project setup
        self.cp, self.func_resolver, self.is_permanence_on, self.permanence_client = Helper.setup_project(self.kwargs)

        # Initialize the CAI (computer-agent-interface)
        self.peek_src = PeekSrcSkill(function_resolver=self.func_resolver, **kwargs)
        self.peek_logs = PeekLogsSkill(**kwargs)
        
        if Config.crs_mode == CRSMode.DELTA:
            self.peek_diff = PeekDiffSkill(function_resolver=self.func_resolver, **kwargs)

        # Root cause generator
        self.root_cause_generator = RootCauseGenerator(patcherq=self, function_resolver=self.func_resolver)

        self.build_configuration_id = ''

    def start(self):

        # POI report
        if Config.patcherq_mode == PatcherqMode.PATCH or Config.patcherq_mode == PatcherqMode.REFINE:
            # generate initial context report
            self.poi_report, self.poi_report_meta, self.issue_ticket, self.initial_context_report, self.funcs_in_scope = Helper.get_initial_context_report(patcherq=self)
            self.build_configuration_id = self.poi_report_meta.build_configuration_id
        elif Config.patcherq_mode == PatcherqMode.SARIF:
            self.funcs_in_scope = Helper.get_funcs_in_scope_sarif(patcherq=self)
            self.build_configuration_id = ''

        # Initializing patching utils
        root_cause_reports = set()
        successful_patch_attempts = dict()
        patch_generator = PatchGenerator(self.cp, self.func_resolver, self.kwargs)

        # #############################################
        # 🔄💰
        # This is the loop that implements the recovery 
        # from LLM budget exceptions.
        ###############################################
        while True:
            
            ##########################################################################################
            # 🔄📜
            # Iterate over all the root-cause reports we have (e.g., dyva, triage, etc...)
            # NOTE: the root_cause_generator yields the reports one by one.
            ##########################################################################################
            for root_cause_report_id, root_cause_report in enumerate(self.root_cause_generator.reports()):
                
                if not root_cause_report:
                    logger.info(' Root cause report from %s is invalid. Fetching the next one.\n', root_cause_report_id)
                    continue
                
                root_cause_reports.add(root_cause_report)

                # Iterate over programmer llms
                programmer = Programmer(
                                        patcherq=self,
                                        root_cause_report_id=root_cause_report_id, 
                                        root_cause_report=root_cause_report, 
                                        patch_generator=patch_generator,
                                        successful_patch_attempts=successful_patch_attempts,
                                        sanitizers=(self.poi_report_meta.consistent_sanitizers if Config.patcherq_mode in (PatcherqMode.PATCH, PatcherqMode.REFINE) else []),
                                        )
                
                # Feedback Loop
                while programmer.patch_state != 'stop':
                    programmer.generate()
                    if programmer.patch_state == "giveup":
                        # NOTE: bad bad stuff happened, give up this programmer.
                        #       e.g., MaxToolCalls.
                        break
                    if programmer.patch_state == 'success':
                        patched_cp = programmer.verify()

                # NOTE if we are here it's either an early giveup, or, a stop!
                if programmer.patch_state == "giveup":
                    # NOTE: this goes to the next root cause report (🚗🔄📜), not the budget loop.
                    continue
                
                # NOTE: in this case, it's a stop and we have a patch
                #       so, check and save.
                if programmer.patch_verified:
                    programmer.save(patched_cp=patched_cp)
                else:
                    logger.info('👎 Patch from root-cause %s could not be verified!\n', root_cause_report_id)

                # Greedy patching check
                if Config.greedy_patching and len(successful_patch_attempts) > 0:
                    logger.info('🐍 Greedy patching enabled, stopping at the first successful patch\n')
                    # NOTE: this only breaks the root cause loop (⛓️‍💥🔄📜), not the budget loop.
                    break
                else:
                    # We have a successful patch, but we want to keep going to see if we can get more.
                    # So now we go to the next root cause report.
                    # NOTE: this goes to the next root cause report (🚗🔄📜), not the budget loop.
                    continue
            ###########################################🔄📜##################################################

            if len(successful_patch_attempts) == 0:
                # ❌ 
                # We DO NOT have a valid patch attempt.
                # We might want to give it another try if we have missing reports.
                if self.root_cause_generator.check_missing_reports():

                    # NOTE: So if we are here, it means we DO MISS some root cause reports.
                    
                    # In this case, we take a nap until the next budget tick if we are in nap mode.
                    if Config.nap_mode == True and self.root_cause_generator.how_many_naps < Config.nap_becomes_death_after:
                        logger.info(f'😴 Taking nap number {self.root_cause_generator.how_many_naps}...')
                        self.root_cause_generator.how_many_naps += 1
                        self.root_cause_generator.take_a_nap()
                    else:
                        # We DO have missing reports, but we are not in nap mode 
                        # or we have napped too much...get rekt...
                        # NOTE: this will break the budget loop (⛓️‍💥🔄💰).
                        break
                else:
                    # OK, we have no missing reports 
                    # and we fail to patch...get rekt...
                    # NOTE: this will break the budget loop (⛓️‍💥🔄💰).
                    break
            else:
                # ✅ 
                # We DO have a successful patch, but we might want to keep going to see if we can get more.
                # (if we have missing root-cause reports)
                if self.root_cause_generator.check_missing_reports():
                    if Config.greedy_patching:
                        # We are in greedy patching mode, so we do not 
                        # care about the missing reports.
                        # NOTE: this will break the budget loop (⛓️‍💥🔄💰).
                        break
                    else:
                        # We have a successful patch and not in greedy
                        # we want to see if we can get more!
                        # NOTE: this will continue the budget loop (🚗🔄💰).
                        continue
                else:
                    # We have a successful patch and no missing reports.
                    # This is a stop in any situation.
                    # So we can break the budget loop.
                    # NOTE: this will break the budget loop (⛓️‍💥🔄💰).
                    break

        ########################################🔄💰################################################

        logger.info(' ========== Patching process completed! ========== \n')
        total_cost = agentlib.lib.agents.agent.global_event_dumper.total_cost_per_million / 1_000_000
        logger.info(' 💸 Total cost of the patching process: %s\n', total_cost)

        # Save info
        record_id = datetime.now().strftime("%Y-%m-%d-%H-%M")
        Helper.save_successful_patch_attempts(id=record_id, successful_patch_attempts=successful_patch_attempts)
        Helper.save_root_cause_reports(id=record_id, root_cause_reports=root_cause_reports)
        
        # Generate Sarif
        if Config.generate_sarif:
            programmer.make_sarif(successful_patch_attempts)

        if len(successful_patch_attempts) > 0:
            # Signal the pipeline that we have a successful patch 🍾
            exit(0)
        else:
            # Signal the pipeline that we have no successful patch 😢
            exit(1)

'''
              __         .__                 ________   
___________ _/  |_  ____ |  |__   ___________\_____  \  
\____ \__  \\   __\/ ___\|  |  \_/ __ \_  __ \/  / \  \ 
|  |_> > __ \|  | \  \___|   Y  \  ___/|  | \/   \_/.  \
|   __(____  /__|  \___  >___|  /\___  >__|  \_____\ \_/
|__|       \/          \/     \/     \/             \__>
'''
def main(**kwargs):

    # Preparation if the patcherq mode is refinement
    if Config.patcherq_mode == PatcherqMode.REFINE:
        # In a refinement job we are getting the ID of a failing patch.
        # So here we are gonna fetch the failing patch and all the related information (connected POI reports and crashing inputs)
        failing_patch_key = kwargs['failing_patch_id']
        failing_patch_info = Helper.get_failing_patch_info(failing_patch_key)
        try:
            failing_patch_node = failing_patch_info[0][0]
            failing_patch = FailedPatch(key=failing_patch_node.patch_key, diff=failing_patch_node.diff)
        except Exception as e:
            logger.error(' 🫢 Error while fetching the failing patch info: %s', e)
            exit(1)

        # NOTE: here we will store our classes instead of neomodel classes
        crashing_inputs = []

        try:
            crashing_input_nodes = Helper.get_crashing_inputs_from_bucket(kwargs['bucket_id'])
            for crashing_input_node in crashing_input_nodes:
                ci = CrashingInput(crashing_input_hex=crashing_input_node[0].content_hex, crashing_input_hash=crashing_input_node[0].content_hash)
                crashing_inputs.append(ci)
        except Exception as e:
            logger.error(f' 🫢 Error while fetching the crashing inputs from the analysis graph: {e}. This is not FATAL, continuing.')
        
        # Now adding the NEW crashing input as received by the pipeline (the one that caused the new POI report)
        try:
            with open(kwargs['crashing_input_path'], 'rb') as file:
                crash_input_bytes = file.read()
                crash_input_hash = hashlib.sha256(crash_input_bytes).hexdigest()
                crash_input_hex = crash_input_bytes.hex()
                ci = CrashingInput(crashing_input_hex=crash_input_hex, crashing_input_hash=crash_input_hash)
                crashing_inputs.append(ci)
        except Exception as e:
            logger.error(f' 🥹 Error while processing the new crashing input: {e}')
            # NOTE: well in this case we are doomed.
            exit(1)
        
        # Add these to the kwargs
        kwargs['failing_patch'] = failing_patch

        # Handle the `use_reg_pass`
        Config.use_reg_pass = False
    
    elif Config.patcherq_mode == PatcherqMode.PATCH:
        crashing_inputs = []
        with open(kwargs['crashing_input_path'], 'rb') as file:
            crash_input_bytes = file.read()
            crash_input_hash = hashlib.sha256(crash_input_bytes).hexdigest()
            crash_input_hex = crash_input_bytes.hex()
            ci = CrashingInput(crashing_input_hex=crash_input_hex, crashing_input_hash=crash_input_hash)
            crashing_inputs.append(ci)
        
        # Handle the `use_reg_pass`
        if Config.use_reg_pass:          
            if 'bucket_id' not in kwargs or not kwargs['bucket_id']:
                logger.error('🫢 `use_reg_pass` is enabled but the `bucket_id` is not available, so we are disabling it')
                Config.use_reg_pass = False
    else:
        # Handle the `use_reg_pass`
        Config.use_reg_pass = False
        crashing_inputs = []
    
    kwargs['crashing_inputs_to_test'] = crashing_inputs

    # Instantiating the PatcherQ class!
    patcherQ = PatcherQ(**kwargs)
    patcherQ.start()
