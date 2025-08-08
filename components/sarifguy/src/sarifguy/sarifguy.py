import os
import argparse
import logging 
import yaml
import hashlib
import json
import agentlib 
import time 

from datetime import datetime, timedelta
from enum import Enum
from agentlib.lib.common import LLMApiBudgetExceededError, LLMApiRateLimitError
from shellphish_crs_utils.function_resolver import RemoteFunctionResolver, LocalFunctionResolver
from shellphish_crs_utils.models.oss_fuzz import AugmentedProjectMetadata
from shellphish_crs_utils.models.aixcc_api import SARIFMetadata, Assessment
from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject
from shellphish_crs_utils.sarif_resolver import SarifResolver, DumbSarifResolver

from analysis_graph.api import add_sarif_report


from .toolbox import PeekSrcSkill, PeekSrcSkillDumb
from .agents import SarifTriageGuy
from .config import Config

logger = logging.getLogger("sarifguy")
logger.setLevel(logging.INFO)
log = logger


SARIFguy_modes = ['dumb', 'reasonable']



true_positive_art = '''
  __                                             .__  __  .__              
_/  |________ __ __   ____   ______   ____  _____|__|/  |_|__|__  __ ____  
\   __\_  __ \  |  \_/ __ \  \____ \ /  _ \/  ___/  \   __\  \  \/ // __ \ 
 |  |  |  | \/  |  /\  ___/  |  |_> >  <_> )___ \|  ||  | |  |\   /\  ___/ 
 |__|  |__|  |____/  \___  > |   __/ \____/____  >__||__| |__| \_/  \___  >
                         \/  |__|              \/                       \/ 
'''

false_positive_art = '''
  _____       .__                                      .__  __  .__            ._.
_/ ____\____  |  |   ______ ____   ______   ____  _____|__|/  |_|__|__  __ ____| |
\   __\\__  \ |  |  /  ___// __ \  \____ \ /  _ \/  ___/  \   __\  \  \/ // __ \ |
 |  |   / __ \|  |__\___ \\  ___/  |  |_> >  <_> )___ \|  ||  | |  |\   /\  ___/\|
 |__|  (____  /____/____  >\___  > |   __/ \____/____  >__||__| |__| \_/  \___  >_
            \/          \/     \/  |__|              \/                       \/\/
'''

class SARIFguy:
    def __init__(self, **kwargs):
        
        all_args = kwargs

        self.mode = all_args.get("mode", None)
        assert self.mode in SARIFguy_modes, f"Unknown mode: {self.mode}. Supported modes are: {SARIFguy_modes}"

        self.sarif_path = all_args.get("sarif_path")
        self.sarif_meta = SARIFMetadata.model_validate(yaml.safe_load(all_args["sarif_meta"].read_text()))
        self.out_path = all_args.get("out_path")
        self.sarif_assessment_out_path = all_args.get("out_path")
        self.sarifguy_heartbeat_path = all_args.get("sarifguy_heartbeat_path")
        
        self.project_name = all_args.get("project_name")
        self.oss_fuzz_project = all_args.get("oss_fuzz_project")
        self.oss_fuzz_project_src = all_args.get("oss_fuzz_project_src")

        # NOTE: THIS IS AN ****UNBUILT***** OSSFuzzProject 
        self.cp_debug = OSSFuzzProject(
                                       project_id = self.sarif_meta.pdt_task_id,
                                       oss_fuzz_project_path = self.oss_fuzz_project,
                                       project_source = self.oss_fuzz_project_src,
                                       use_task_service = False
                                      )

        self.project_language = self.cp_debug.project_language.value

        # Little translation from languages string
        # (I am not waiting for the project metadata, so I need to this ugly thing here)
        if self.project_language == "c++":
            self.project_language = "c"
        
        
        if self.mode == "reasonable":
            self.functions_index = all_args.get("functions_index")
            self.function_jsons_dir = all_args.get("functions_jsons_dir")

            if all_args['local_run'] == "True":
                self.function_resolver = LocalFunctionResolver(
                    functions_index_path=str(self.functions_index),
                    functions_jsons_path=str(self.function_jsons_dir),
                )
            else:
                self.function_resolver = RemoteFunctionResolver(
                    self.project_name,
                    self.sarif_meta.pdt_task_id
                )

            logger.info(f"🧰 Instantiating peek_src_skill")
            self.peek_src = PeekSrcSkill(
                    function_resolver=self.function_resolver,
                    cp=self.cp_debug
            )

            # NOTE: this is to resolve DumbSarifLocation (locations that cannot be resolved with the func resolver.)
            self.peek_src_dumb = PeekSrcSkillDumb(
                    cp=self.cp_debug
            )
            
            self.sarif_resolver = SarifResolver(
                self.sarif_path, self.function_resolver
                )

        self.curr_llm_index = 0
        self.how_many_naps = 0


    def take_a_nap(self):
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

    def emit_assesment(self, verdict, summary, fake=False):
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

        if fake:
            logger.info(f'🧸 Emitting fake assessment report to {self.sarif_assessment_out_path}')
        else:
            logger.info(f" 📑 Emitting assessment report to {self.sarif_assessment_out_path}")
            if verdict == "TP":
                logger.info(f"    - Verdict: {verdict} 👍")
            else:
                logger.info(f"    - Verdict: {verdict} 👎")

        # Write the dictionary as yaml into the output path
        with open(self.sarif_assessment_out_path, 'w') as f:
            f.write(sarif_metadata_output.model_dump_json(indent=2))


    def switch_sarif_guy_llm(self, sarif_tg_guy: SarifTriageGuy) -> SarifTriageGuy:
        sarifguy_llm = Config.sarif_tg_guy_llms[self.curr_llm_index]
        logger.info(f'🔄🤖 Switching sarifGuy to model: {sarifguy_llm}')
        sarif_tg_guy.__LLM_MODEL__ = sarifguy_llm
        sarif_tg_guy.llm  = sarif_tg_guy.get_llm_by_name(
                                                         sarifguy_llm, 
                                                         **sarif_tg_guy.__LLM_ARGS__,
                                                         raise_on_budget_exception=sarif_tg_guy.__RAISE_ON_BUDGET_EXCEPTION__,
                                                         raise_on_rate_limit_exception=sarif_tg_guy.__RAISE_ON_RATE_LIMIT_EXCEPTION__
                                                        ) 
        
        self.peek_src.clean_tool_call_history()
        self.peek_src_dumb.clean_tool_call_history()
        
        return sarif_tg_guy

    def dumb_sarifguy(self):
        log.info(f"🤪 Switching to dumb SARIFguy against: {self.sarif_path}")

        # NOTE: sanity check one, is the sarif valid at all?
        if not self.sarif_resolver.is_valid():
            logger.info(f"  🤪💩 The SARIF report is not valid")
            self.emit_assesment("FP", "The SARIF report is not in a valid format.")
            return

        # Get all the results from the sarif report
        sarif_results = self.sarif_resolver.get_dumb_results()

        # NOTE: sanity check two, are there results?
        if len(sarif_results) == 0:
            logger.info(f"🤪💩 The SARIF report has no results")
            self.emit_assesment("FP", "The SARIF report has no results")
            return

        # NOTE: Let's use the SarifTriageGuy to analyze every 
        #       SarifResult we have in the list
        for sarif_id, sarif_result in enumerate(sarif_results):
            logger.info(f"  - Analyzing SARIF result {sarif_id} with DumbSarifTriageGuy")
            self.curr_llm_index = 0
            
            sarif_tg_guy = SarifTriageGuy(
                                        sarifguy_mode=self.mode,
                                        language=self.project_language,
                                        project_name=self.project_name,
                                        rule_id=sarif_result.rule_id,
                                        sarif_message=sarif_result.message,
                                        locs_in_scope=sarif_result.locations,
                                        data_flows=sarif_result.codeflows,
                                        )
            
            # Set the first LLM model to use
            sarif_guy_llm = Config.sarif_tg_guy_llms[self.curr_llm_index]
            sarif_tg_guy.__LLM_MODEL__ = sarif_guy_llm
            sarif_tg_guy.llm  = sarif_tg_guy.get_llm_by_name(
                                                             sarif_guy_llm, 
                                                             **sarif_tg_guy.__LLM_ARGS__,
                                                             raise_on_budget_exception=sarif_tg_guy.__RAISE_ON_BUDGET_EXCEPTION__,
                                                             raise_on_rate_limit_exception=sarif_tg_guy.__RAISE_ON_RATE_LIMIT_EXCEPTION__
                                                            ) 

            # 🧠 Reasoning loop
            #    - This is basically handling any weirdness happening 
            #      during the LLM reasoining process (e.g., no budget left, context exceeded, etc.)
            while True:
                try:
                    res = sarif_tg_guy.invoke()
                    self.how_many_naps = 0
                    # Get out of the reasoning loop!
                    # 🧠⛓️‍💥
                    break
                except (LLMApiBudgetExceededError, LLMApiRateLimitError) as e:
                    # NOTE: this exception can potentially happens midway through the reasoning.
                    # TODO: if we are midway, shall we do brain surgery and transplant the current history into another LLM and continue from there?
                    # NOTE: this exception can potentially happens midway through the reasoning.
                    if isinstance(e, LLMApiRateLimitError):
                        logger.critical(f' 😭 LLM API rate limit exceeded for {sarif_tg_guy.__LLM_MODEL__}!')
                    else:
                        logger.critical(f' 😭 LLM API budget exceeded for {sarif_tg_guy.__LLM_MODEL__}!')

                    self.curr_llm_index += 1

                    if self.curr_llm_index >= len(Config.sarif_tg_guy_llms):
                        logger.info(f' 😶‍🌫️ No more LLMs to try. SarifGuy goes to sleep!')

                        # Reset the LLM index
                        self.curr_llm_index = 0
                        
                        if Config.nap_mode == True and self.how_many_naps < Config.nap_becomes_death_after:
                            self.how_many_naps += 1
                            logger.info(f'😴 Taking nap number {self.how_many_naps}...')
                            
                            # 😴
                            self.take_a_nap()

                            logger.info(f'🫡 Nap time is over! Back to work...')
                            sarif_tg_guy = self.switch_sarif_guy_llm(sarif_tg_guy)

                            # 🧠▶️
                            continue
                        else:
                            total_cost = agentlib.lib.agents.agent.global_event_dumper.total_cost_per_million / 1_000_000
                            logger.info(f' 💸 Total cost of the failing sarifguy process: {total_cost}\n')

                            # 🧠⛓️‍💥
                            exit(1)
                    else:
                        # NOTE: we have more LLMs to try, so we just switch the LLM and keep going
                        sarif_tg_guy = self.switch_sarif_guy_llm(sarif_tg_guy)

                        # 🧠▶️
                        continue
                
                except Exception as e:
                    logger.critical(f' 😱 Something went wrong with the reasoning: {e}')
                    total_cost = agentlib.lib.agents.agent.global_event_dumper.total_cost_per_million / 1_000_000
                    logger.info(f' 💸 Total cost of the failing sarifguy process: {total_cost}\n')

                    # 🧠⛓️‍💥
                    exit(1)
            # 🧠 
            # =======================================================================================
            
            verdict = res.value['verdict']
            summary = res.value['summary']

            logger.info(f"🤪 Got summary from DumbSarifTriageGuy: {summary}")

            if verdict == "TP":
                logger.info(f"  🤪 DumbSarifTriageGuy thinks this is a true positive")
                self.emit_assesment(verdict, summary)
            elif verdict == "FP":
                logger.info(f"  🤪 DumbSarifTriageGuy thinks this is a false positive")
                self.emit_assesment(verdict, summary)
            else:
                logger.info(f"  🤪 DumbSarifTriageGuy is just dumb....")
                self.emit_assesment(verdict, summary)


    def reasonable_sarifguy(self):
        log.info(f"🧐 Running reasonable SARIFguy against: {self.sarif_path}")

        # NOTE: sanity check one, is the sarif valid at all?
        if not self.sarif_resolver.is_valid():
            logger.info(f"  🤪💩 The SARIF report is not valid")
            self.emit_assesment("FP", "The SARIF report is not in a valid format.")
            return

        # Get all the results from the sxarif report
        sarif_results = self.sarif_resolver.get_results()
        
        # NOTE: sanity check two, are there good results?
        if len(sarif_results) != 0:
            logger.info(f" The SARIF report has {len(sarif_results)} results")
        elif len(self.sarif_resolver.dumb_sarif_results) != 0:
            logger.info(f" The SARIF report has {len(self.sarif_resolver.dumb_sarif_results)} dumb results")
            # NOTE: in this case we have results for which the function resolver
            #       could not do much.
            #       Let's call the dumb sarifguy in this case!
            self.mode = "dumb"
            self.dumb_sarifguy()

            # 🌐⬆️
            # NOTE: also upload this report to the analysis graph.
            covered_funcs_list = []
            add_sarif_report(
                sarif_uid=self.sarif_meta.pdt_sarif_id,
                sarif_type="injected",
                sarif_path=self.sarif_path,
                covered_functions_keys=covered_funcs_list
            )
            return
        else:
            self.emit_assesment("FP", "The SARIF report has no results")
            return

        #############################################################################
        # 🌐⬆️
        #############################################################################
        # NOTE: reasonable sarifguy is gonna upload the SarifReport
        # in the analysis graph (it has a function resolver so I trust the locations)
        #############################################################################
        #############################################################################
        covered_functions_keys = set()
        for sarif_result in sarif_results:
            for loc in sarif_result.locations:
                covered_functions_keys.add(loc.keyindex)
            for codeflow in sarif_result.codeflows:
                for loc in codeflow.locations:
                    covered_functions_keys.add(loc.keyindex)

        add_sarif_report(
            sarif_uid=self.sarif_meta.pdt_sarif_id,
            sarif_type="injected",
            sarif_path=self.sarif_path,
            covered_functions_keys=covered_functions_keys
        )

        # NOTE: Let's use the SarifTriageGuy to analyze every 
        #       SarifResult we have in the list
        for sarif_id, sarif_result in enumerate(sarif_results):
            logger.info(f"  - Analyzing SARIF result {sarif_id} with SarifTriageGuy")
            self.curr_llm_index = 0
            
            sarif_tg_guy = SarifTriageGuy(
                                        sarifguy_mode=self.mode,
                                        language=self.project_language,
                                        project_name=self.project_name,
                                        rule_id=sarif_result.rule_id,
                                        sarif_message=sarif_result.message,
                                        locs_in_scope=sarif_result.locations,
                                        data_flows=sarif_result.codeflows,
                                        )

            # Set the first LLM model to use
            sarif_guy_llm = Config.sarif_tg_guy_llms[self.curr_llm_index]
            sarif_tg_guy.__LLM_MODEL__ = sarif_guy_llm
            sarif_tg_guy.llm  = sarif_tg_guy.get_llm_by_name(
                                                             sarif_guy_llm, 
                                                             **sarif_tg_guy.__LLM_ARGS__,
                                                             raise_on_budget_exception=sarif_tg_guy.__RAISE_ON_BUDGET_EXCEPTION__,
                                                             raise_on_rate_limit_exception=sarif_tg_guy.__RAISE_ON_RATE_LIMIT_EXCEPTION__
                                                            ) 
            logger.info(f'🤖 Running ReasonableSarifTriageGuy with LLM: {sarif_tg_guy.__LLM_MODEL__}')
            # 🧠 Reasoning loop
            #    - This is basically handling any weirdness happening 
            #      during the LLM reasoining process (e.g., no budget left, context exceeded, etc.)
            while True:
                try:
                    res = sarif_tg_guy.invoke()
                    self.how_many_naps = 0
                    # Get out of the reasoning loop!
                    # 🧠⛓️‍💥
                    break
                except (LLMApiBudgetExceededError, LLMApiRateLimitError) as e:
                    # NOTE: this exception can potentially happens midway through the reasoning.
                    if isinstance(e, LLMApiRateLimitError):
                        logger.critical(f' 😭 LLM API rate limit exceeded for {sarif_tg_guy.__LLM_MODEL__}!')
                    else:
                        logger.critical(f' 😭 LLM API budget exceeded for {sarif_tg_guy.__LLM_MODEL__}!')
                    
                    self.curr_llm_index += 1

                    if self.curr_llm_index >= len(Config.sarif_tg_guy_llms):
                        logger.info(f' 😶‍🌫️ No more LLMs to try. SarifGuy goes to sleep!')

                        # Reset the LLM index
                        self.curr_llm_index = 0
                        
                        if Config.nap_mode == True and self.how_many_naps < Config.nap_becomes_death_after:
                            self.how_many_naps += 1
                            logger.info(f'😴 Taking nap number {self.how_many_naps}...')
                            self.take_a_nap()
                            logger.info(f'🫡 Nap time is over! Back to work...')
                            # NOTE: we reset the curr_llm_index, so we are restarting from the beginning!
                            sarif_tg_guy = self.switch_sarif_guy_llm(sarif_tg_guy)

                            # 🧠▶️
                            continue
                        else:
                            total_cost = agentlib.lib.agents.agent.global_event_dumper.total_cost_per_million / 1_000_000
                            logger.info(f' 💸 Total cost of the failing sarifguy process: {total_cost}\n')
                            
                            # 🧠⛓️‍💥
                            exit(1)
                    else:
                        # NOTE: we have more LLMs to try, so we just switch the LLM and keep going
                        sarif_tg_guy = self.switch_sarif_guy_llm(sarif_tg_guy)

                        # 🧠▶️
                        continue

            # 🧠 End of the while reasoning loop, we are out of the LLM
            # =======================================================================================

            verdict = res.value['verdict']
            summary = res.value['summary']

            logger.info(f"🧐 Got summary from ReasonableSarifTriageGuy: {summary}")

            if verdict == "TP":
                logger.info(f"  🧐 ReasonableSarifTriageGuy thinks this is a true positive")
                self.emit_assesment(verdict, summary)
            elif verdict == "FP":
                logger.info(f"  🧐 ReasonableSarifTriageGuy thinks this is a false positive")
                self.emit_assesment(verdict, summary)
            else:
                # FIXME: maybe recover and tell Claude it is full of lies.
                logger.info(f"  🧐 ReasonableSarifTriageGuy is just dumb....")
                exit(1)

    def run(self):

        # NOTE: for safety, we write these files now. These files will be uploaded to pdt
        #       NO MATTER WHAT HAPPENS because we set set_failure_ok = True in pipeline.yaml.
        self.emit_assesment("TP", "This is just a safe assessment report to make sure the SARIFguy is running properly.", fake=True)

        if self.mode == "dumb":
            # NOTE: This mode is not used anymore. The only way that sarifguy 
            # becomes "dumb" is if we have DumbSarifResults in the SARIF report.
            self.dumb_sarifguy()
        elif self.mode == "reasonable":
            self.reasonable_sarifguy()
        else:
            raise ValueError(f"Unknown mode: {self.mode}")

'''
  _________            .__  _____  ________              
 /   _____/____ _______|__|/ ____\/  _____/ __ __ ___.__.
 \_____  \\__  \\_  __ \  \   __\/   \  ___|  |  <   |  |
 /        \/ __ \|  | \/  ||  |  \    \_\  \  |  /\___  |
/_______  (____  /__|  |__||__|   \______  /____/ / ____|
        \/     \/                        \/       \/     
'''
def main(**kwargs):
    sarifGuy = SARIFguy(**kwargs)
    sarifGuy.run()
