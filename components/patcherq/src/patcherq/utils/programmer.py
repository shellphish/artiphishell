import os
import yaml
import json
import hashlib
import logging
import agentlib
import time 
import random

from datetime import datetime, timedelta
from pathlib import Path

from agentlib.lib.common import LLMApiBudgetExceededError, LLMApiRateLimitError
from shellphish_crs_utils.models.patch import PatchMetaData, PatchBypassRequestMeta
from analysis_graph.models import crashes as analysis_graph_crash_reports

from ..config import Config, PatcherqMode
from ..agents import ProgrammerGuy, SARIFGuy, CriticGuy
from ..patch_generator import PatchGenerator
from ..patch_generator.exceptions import PatchIsDuplicate, IncorrectFilePathException, WrongPatchLocationException, IllegalPatchLocationException, PatchFailedSanitization

from ..patch_verifier import PatchVerifier
from ..patch_verifier.exceptions import PatchedCodeDoesNotCompile, PatchedCodeStillCrashes, PatchedCodeHangs, PatchedCodeDoesNotPassTests, PatchedCodeDoesNotPassCritic, PatchedCodeDoesNotPassBuildPass
from ..patch_verifier.exceptions.errors import FailureCodes

from ..agents.exceptions import MaxToolCallsExceeded

from typing import List, Dict, Any, Union

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class Programmer:
    def __init__(
        self, 
        patcherq,
        root_cause_report_id: str, 
        root_cause_report: str, 
        patch_generator: PatchGenerator,
        successful_patch_attempts: dict,
        sanitizers: List[str] = None,
    ):
        # Import patcherq stuff
        self.patcherq = patcherq
        
        # Params for me
        self.curr_programmer_llm_index = 0
        self.programmer_llm = Config.programmer_llms[self.curr_programmer_llm_index]
        self.root_cause_report_id = root_cause_report_id
        self.root_cause_report = root_cause_report
        self.patch_generator = patch_generator
        self.successful_patch_attempts = successful_patch_attempts
        self.sanitizers = sanitizers

        # The programmer guy is the agent that will be responsible for generating the patch
        # for the vulnerability.
        if Config.patcherq_mode == PatcherqMode.PATCH or Config.patcherq_mode == PatcherqMode.SARIF:
            self.programmer_guy = ProgrammerGuy(
                                                llm_model=self.programmer_llm,
                                                root_cause_report=str(self.root_cause_report), 
                                                project_language=self.patcherq.project_language, 
                                                with_codeql_server=Config.use_codeql_server, 
                                                with_lang_server=Config.use_lang_server,
                                                with_sanitizers=self.sanitizers,
                                                funcs_in_scope=self.patcherq.funcs_in_scope
                                            )
        else:
            # In refinement mode, we want to tell programmerGuy a few extra hints
            self.programmer_guy = ProgrammerGuy(
                                                llm_model=self.programmer_llm,
                                                root_cause_report=str(self.root_cause_report), 
                                                project_language=self.patcherq.project_language, 
                                                with_codeql_server=Config.use_codeql_server, 
                                                with_lang_server=Config.use_lang_server,
                                                with_sanitizers=self.sanitizers,
                                                refine_job=True,
                                                failed_functionality=self.patcherq.failed_functionality,
                                                num_crashing_inputs_to_pass=len(self.patcherq.crashing_inputs_to_test),
                                                funcs_in_scope=self.patcherq.funcs_in_scope
                                            )

        self.programmer_guy.__LLM_MODEL__ = self.programmer_llm
        self.programmer_guy.llm  = self.programmer_guy.get_llm_by_name(
                                                                       self.programmer_llm, 
                                                                       **self.programmer_guy.__LLM_ARGS__,
                                                                       raise_on_budget_exception=self.programmer_guy.__RAISE_ON_BUDGET_EXCEPTION__,
                                                                       raise_on_rate_limit_exception=self.programmer_guy.__RAISE_ON_RATE_LIMIT_EXCEPTION__
                                                                      )
        
        # The tool call guards need to be cleaned every time we create a new agent
        self.patcherq.peek_src.clean_tool_call_history()
        self.patcherq.peek_logs.clean_tool_call_history()
        
        # The current state of the patch: 
        #  - "begin" | the patch is just starting
        #  - "no-compile" | the patch does not compile
        #  - "still-crash" | the patch still crashes
        #  - "no-tests" | the patch does not pass the tests
        self.patch_state = 'begin'
        # This is the total number of attempts for this programmerGuy
        self.programmer_total_attempts = 0
        # How many times we tried to compile in a row and failed 
        self.programmer_compile_attempt_number = 0
        # How many times we tried to run the program in a row and it crashed
        self.programmer_crash_attempt_number = 0
        # How many times we tried to run the tests in a row and they failed
        self.programmer_tests_attempt_number = 0
        # How many times duplicate patches were hit
        self.programmer_patch_duplicate_number = 0

        # Patch verification
        self.patch_verified = False
        self.build_request_id = None

        # How many times we nap because of budget exhaustion
        self.how_many_naps = 0

    def take_a_nap(self):
        # NOTE: this will make pQ nap until the next budget tick.
        logger.info('😴 Nap time! I will be back in a bit...')
        # Go to the next multiple of Config.nap_duration
        # For example, if Config.nap_duration is 5, and the current minute is 12,
        # we will wake up at 15.
        waking_up_at = datetime.now() + timedelta(minutes=Config.nap_duration - (datetime.now().minute % Config.nap_duration))

        while True:
            if datetime.now() >= waking_up_at:
                logger.info('🫡 Nap time is over! Back to work...')
                break
            else:
                time.sleep(Config.nap_snoring)

    def switch_programmer_guy_llm(self):
        self.programmer_llm = Config.programmer_llms[self.curr_programmer_llm_index]
        logger.info('🔄🤖 Switching programmerGuy to model: %s', self.programmer_llm)
        if not Config.programmer_brain_surgery:
            # Give birth to new programmer guy!
            if Config.patcherq_mode == PatcherqMode.PATCH or Config.patcherq_mode == PatcherqMode.SARIF:
                self.programmer_guy = ProgrammerGuy(
                                                root_cause_report=str(self.root_cause_report), 
                                                project_language=self.patcherq.project_language, 
                                                with_codeql_server=Config.use_codeql_server, 
                                                with_lang_server=Config.use_lang_server,
                                                with_sanitizers=self.sanitizers,
                                                funcs_in_scope=self.patcherq.funcs_in_scope
                                            )
            else:
                # In refinement mode, we want to tell programmerGuy a few extra hints
                self.programmer_guy = ProgrammerGuy(
                                                root_cause_report=str(self.root_cause_report), 
                                                project_language=self.patcherq.project_language, 
                                                with_codeql_server=Config.use_codeql_server, 
                                                with_lang_server=Config.use_lang_server,
                                                with_sanitizers=self.sanitizers,
                                                refine_job=True,
                                                num_crashing_inputs_to_pass=len(self.patcherq.crashing_inputs_to_test),
                                                funcs_in_scope=self.patcherq.funcs_in_scope
                                            )
            self.programmer_total_attempts = 0
            self.programmer_compile_attempt_number = 0
            self.programmer_crash_attempt_number = 0
            self.programmer_tests_attempt_number = 0
            self.programmer_patch_duplicate_number = 0

        self.programmer_guy.__LLM_MODEL__ = self.programmer_llm
        self.programmer_guy.llm  = self.programmer_guy.get_llm_by_name(
                                                                       self.programmer_llm, 
                                                                       **self.programmer_guy.__LLM_ARGS__,
                                                                       raise_on_budget_exception=self.programmer_guy.__RAISE_ON_BUDGET_EXCEPTION__,
                                                                       raise_on_rate_limit_exception=self.programmer_guy.__RAISE_ON_RATE_LIMIT_EXCEPTION__
                                                                       ) 
        # The tool call guards need to be cleaned every time we create a new agent
        self.patcherq.peek_src.clean_tool_call_history()
        self.patcherq.peek_logs.clean_tool_call_history()

    def generate(self):
        # =============================
        # 🔄 HANDLING THE FEEDBACK LOOP
        # =============================
        if self.programmer_total_attempts > Config.max_programmer_total_attempts:
            logger.info('✋🏼 Maximum number of total attempts for this programmerGuy! %s\n', self.programmer_total_attempts)
            # stoping feedback loop
            self.patch_state = 'stop'
            return 
            
        # ===================
        # 🌱 PATCH GENERATION
        # ===================
        logger.info('🕵🏻 ProgrammerGuy Running...! %s\n', self.programmer_guy.__LLM_MODEL__)
        logger.info('  - Root-cause report ID: ID-%s\n', self.root_cause_report_id)
        logger.info('  - Patch state: %s\n', self.patch_state)
        logger.info('  - Total attempts: %s/%s\n', self.programmer_total_attempts, Config.max_programmer_total_attempts)
        logger.info('    - 🏠 Compile attempted: %s/%s\n', self.programmer_compile_attempt_number, Config.max_programmer_attempts_compile)
        logger.info('    - 💥 Crash attempted: %s/%s\n', self.programmer_crash_attempt_number, Config.max_programmer_attempts_crash)
        logger.info('    - 🧪 Tests attempted: %s/%s\n', self.programmer_tests_attempt_number, Config.max_programmer_attempts_tests)

        # =======================================================================================
        # 🧠 Reasoning loop
        #    - This is basically handling any weirdness happening 
        #      during the LLM reasoining process (e.g., no budget left, context exceeded, etc.)
        while True:
            try:
                res = self.programmer_guy.invoke()
                # NOTE: if the invoke goes through, we can reset the nap counter
                self.how_many_naps = 0
                # Get out of the reasoning loop!
                break
            except MaxToolCallsExceeded:
                logger.critical(f'😭 Max tool calls exceeded for Programmer!')
                self.patch_state = 'giveup'
                return
            except (LLMApiBudgetExceededError, LLMApiRateLimitError) as e:
                
                if isinstance(e, LLMApiBudgetExceededError):
                    logger.warning(f'💸 LLM API budget exceeded for {self.programmer_guy.__LLM_MODEL__}!')
                else:
                    logger.warning(f'⌛️ LLM API rate limit exceeded for {self.programmer_guy.__LLM_MODEL__}!')

                self.curr_programmer_llm_index += 1

                if self.curr_programmer_llm_index >= len(Config.programmer_llms):
                    logger.info(' 😶‍🌫️ No more LLMs to try. pQ go to sleep!')

                    # Reset the LLM index
                    self.curr_programmer_llm_index = 0
                    
                    if Config.nap_mode == True and self.how_many_naps < Config.nap_becomes_death_after:
                        self.how_many_naps += 1
                        logger.info('😴 Taking nap number %s...', self.how_many_naps)
                        self.take_a_nap()
                        logger.info('🫡 Nap time is over! Back to work...')
                        # NOTE: we reset the curr_programmer_llm_index, so we are restarting from the beginning!
                        self.switch_programmer_guy_llm()
                    else:
                        # NOTE: in this case, we rollback to the original behavior, early exit because of out of budget.
                        total_cost = agentlib.lib.agents.agent.global_event_dumper.total_cost_per_million / 1_000_000
                        logger.info(' 💸 Total cost of the failing patching process: %s\n', total_cost)
                        exit(1)
                else:
                    # NOTE: we have more LLMs to try, so we just switch the LLM and keep going
                    self.switch_programmer_guy_llm()
                    continue
            except Exception as e:
                # NOTE: this is a generic exception, we should not get here
                #       but if we do, we just log the error and exit
                logger.critical(f'🤡 Unexpected error during ProgrammerGuy invoke: {e}')
                self.patch_state = 'giveup'
                return

        # 🧠 End of the while reasoning loop, we are out of the LLM
        # =======================================================================================

        # raw_patch_attempt is the raw patch that we got from the LLM in the <patch_report> format
        # patch_attempt is an object that describe the patch attempts
        self.raw_patch_attempt, self.patch_attempt = res.value
        logger.info('Patch is:\n %s', self.patch_attempt)

        try:
            # NOTE: the patch_generator returns the git_diff and the updated patch_attempt (correct paths)
            self.git_diff, self.patch_attempt, self.functions_in_patch = self.patch_generator.run(self.patch_attempt)
            # If we got here, we have a new source code with the patch applied! 🎉
            logger.info('✅ Patch generated successfully!\n')
            # set patch state
            self.patch_state = 'success'

        except PatchIsDuplicate as e:
            # NOTE: if a patch is duplicate, we must have an entry in the PatchCache.
            #       in this case, we shortcut the patch verification and just replay 
            #       whatever happen before so we can save a bunch of time!
            self.patch_state = 'duplicate-patch'
            self.programmer_patch_duplicate_number +=1
            
            if self.programmer_patch_duplicate_number <= Config.max_programmer_duplicate_patches:
                action = e.action
                patch_hash = e.patch_hash
                logger.info('♻️ Replaying cached action for patch: %s', patch_hash)
                # Apply the action to the current agent
                action(self.programmer_guy)
            else:
                logger.info('✋🏼 Maximum number of duplicate patches reached for this programmerGuy!')
                # stoping feedback loop
                self.patch_state = 'stop'
            
        except PatchFailedSanitization as e:
            # This is when during sanitization we, for instance,
            # discard ALL the changes proposed in the patch by the LLM.
            # This can happen when it attempts to patch ONLY generated files
            # and we cannot recover from it
            self.patch_state = "bad-patch-sanitizer"
            logger.info('🤡 Patch failed sanitization: %s\n', e.reason)

            # =============================
            # 💾 PatchCache management 
            # =============================
            # This is failed patch, we now store the response for this patch in patch_cache
            patch_hash = hashlib.sha256(str(self.patch_attempt).encode()).hexdigest()
            logger.info('💾 Caching the patch attempt: %s\n', patch_hash)

            cached_action = self.patch_generator.patch_cache.make_cached_action(
                    logger_msg=f'🤡 🔄 Patch failed sanitization: {e.reason}\n',
                    failure_code=FailureCodes.PATCH_DOES_NOT_SANITIZE,
                    feedback_msg=f'The suggested patch does not pass basic validations. These are the errors:\n {e.reason}\n',
                )
            
            self.patch_generator.patch_cache.add_patch(
                                                        patch_hash=patch_hash, 
                                                        raw_patch=self.raw_patch_attempt, 
                                                        patch_attempt=self.patch_attempt, 
                                                        root_cause_report_id=self.root_cause_report_id
                                                    )
            self.patch_generator.patch_cache.set_action(patch_hash, cached_action)
            # =============================

            # Now setting feedback to programmer guy and back to the main loop
            self.programmer_guy.set_feedback(
                                        failure=FailureCodes.PATCH_DOES_NOT_SANITIZE,
                                        feedback=f'The suggested patch does not pass basic validations. These are the errors:\n {e.reason}\n',
                                        extra_feedback=''
                                        )
            self.programmer_total_attempts += 1

        except IllegalPatchLocationException as e:
            # This is when the LLM hallucinates and patch 
            # illegal patches location such as LLVMFuzzerOneInput
            self.patch_state = "illegal-patch"
            logger.info('🤡 Illegal patch location encountered: %s\n', e.reason)

            # =============================
            # 💾 PatchCache management 
            # =============================
            # This is failed patch, we now store the response for this patch in patch_cache
            patch_hash = hashlib.sha256(str(self.patch_attempt).encode()).hexdigest()
            logger.info('   💾 Caching the patch attempt: %s\n', patch_hash)

            cached_action = self.patch_generator.patch_cache.make_cached_action(
                    logger_msg=f'🤡🔄 Illegal patch location encountered: {e.reason}\n',
                    failure_code=FailureCodes.ILLEGAL_PATCH_LOCATION,
                    feedback_msg=f'Illegal patch locations encountered: {e.reason}\n',
                )
            
            self.patch_generator.patch_cache.add_patch(
                                                    patch_hash=patch_hash, 
                                                    raw_patch=self.raw_patch_attempt, 
                                                    patch_attempt=self.patch_attempt, 
                                                    root_cause_report_id=self.root_cause_report_id
                                                    )
            self.patch_generator.patch_cache.set_action(patch_hash, cached_action)
            # =============================

            self.programmer_guy.set_feedback(
                                        failure=FailureCodes.ILLEGAL_PATCH_LOCATION,
                                        feedback=f'Illegal patch locations encountered: {e.reason}\n',
                                        extra_feedback=''
                                        )
            self.programmer_total_attempts += 1

        except WrongPatchLocationException as e:
            # This is when the LLM hallucinates and we cannot recover
            # in the patch generation.
            self.patch_state = "corrupted-patch"
            logger.info('🤡 Wrong patch location encountered: %s\n', e.reason)

            # =============================
            # 💾 PatchCache management 
            # =============================
            # This is failed patch, we now store the response for this patch in patch_cache
            patch_hash = hashlib.sha256(str(self.patch_attempt).encode()).hexdigest()
            logger.info('   💾 Caching the patch attempt: %s\n', patch_hash)

            cached_action = self.patch_generator.patch_cache.make_cached_action(
                    logger_msg=f'🤡🔄 Wrong patch location encountered: {e.reason}\n',
                    failure_code=FailureCodes.CORRUPTED_PATCH,
                    feedback_msg=e.reason,
                )
            
            self.patch_generator.patch_cache.add_patch(
                                                    patch_hash=patch_hash, 
                                                    raw_patch=self.raw_patch_attempt, 
                                                    patch_attempt=self.patch_attempt, 
                                                    root_cause_report_id=self.root_cause_report_id
                                                    )
            self.patch_generator.patch_cache.set_action(patch_hash, cached_action)
            # =============================


            self.programmer_guy.set_feedback(
                                        failure=FailureCodes.CORRUPTED_PATCH, 
                                        feedback=e.reason,
                                        extra_feedback=''
                                        )
            # This fail counts toward the total attempts
            self.programmer_total_attempts += 1

        except IncorrectFilePathException as e:
            self.patch_state = 'incorrect-file-path'
            logger.info('🤡 %s', e)
            logger.info('🛠️ Applying recovery ...')
            
            # =============================
            # 💾 PatchCache management 
            # =============================
            # This is failed patch, we now store the response for this patch in patch_cache
            patch_hash = hashlib.sha256(str(self.patch_attempt).encode()).hexdigest()
            logger.info('   💾 Caching the patch attempt: %s\n', patch_hash)

            cached_action = self.patch_generator.patch_cache.make_cached_action(
                    logger_msg=f'🤡🔄 Incorrect file encountered in patch: {e.reason}\n',
                    failure_code=FailureCodes.CORRUPTED_PATCH,
                    feedback_msg=e.reason,
                )
            
            self.patch_generator.patch_cache.add_patch(
                                                    patch_hash=patch_hash, 
                                                    raw_patch=self.raw_patch_attempt, 
                                                    patch_attempt=self.patch_attempt, 
                                                    root_cause_report_id=self.root_cause_report_id
                                                    )
            self.patch_generator.patch_cache.set_action(patch_hash, cached_action)
            # =============================


            self.programmer_guy.set_feedback(
                                        failure=FailureCodes.CORRUPTED_PATCH, 
                                        feedback=e.reason,
                                        extra_feedback=''
                                        )
            
            # This is when the LLM hallucinates and we cannot recover
            self.programmer_total_attempts += 1
            logger.info('🛠️ Recovery applied!\n')

        except Exception as e:
            logger.info('🤡 Unexpected error during patch generation: %s\n', e)
            # This is an error to fix
            assert False

    def verify(self):
        # =====================
        # 🏆 PATCH VERIFICATION
        # =====================
        logger.info('Running the patch verifier!\n')

        logger.info(" ===== PATCH ATTEMPT =====\n")
        logger.info("%s", self.patch_attempt)
        logger.info(" =========================\n")

        # NOTE: The cp here is the original ****UNBUILT**** cp project. 
        #       The PatchVerifier will make a separate copy to apply the git_diff, compile and verify.
        patch_verifier = PatchVerifier(self.patcherq.cp, self.patch_attempt, self.git_diff, self.functions_in_patch, self.patcherq.project_language, self.root_cause_report, self.patcherq, self.patcherq.kwargs)

        try:
            patched_cp = patch_verifier.run()
            # If we got here, no exception was raised by the patch_verifier
            # thus, we have a verified patch!
            self.patch_verified = True
            # stop feedback loop
            self.patch_state = 'stop'
            self.build_request_id = patch_verifier.build_request_id
            return patched_cp

        except PatchedCodeDoesNotCompile as e:
            logger.info('❌ Patched code does not compile!\n')

            # State variable bookkeeping
            self.patch_state = 'no-compile'
            self.programmer_total_attempts += 1
            self.programmer_compile_attempt_number += 1
            self.programmer_crash_attempt_number = 0
            self.programmer_tests_attempt_number = 0
            
            simple_reason = "The program does not compile after applying the patch!\n"
            simple_reason += f"You can access the logs of the compilation process to see what went wrong at the following path: {e.stderr_log}\n\n"
            simple_reason += f"In particular, the log at {e.stderr_log} contains the stderr and stdout of the compilation process.\n"
            simple_reason += "Keep in mind: the error might be at the end of these logs, so make sure to scroll down if you are not sure what went wrong.\n"
            simple_reason += "Please adjust the proposed patch to resolve the compilation error.\n"

            # =============================
            # 💾 PatchCache management 
            # =============================
            # This is failed patch, we now store the response for this patch in patch_cache
            patch_hash = hashlib.sha256(str(self.patch_attempt).encode()).hexdigest()
            logger.info('   💾 Caching the patch attempt: %s\n', patch_hash)
            
            # NOTE: the error logs are still available (we are creating it with delete=False)
            cached_action = self.patch_generator.patch_cache.make_cached_action(
                    logger_msg=f'❌🔄 Patched code does not compile!\n',
                    failure_code=FailureCodes.PATCHED_CODE_DOES_NOT_COMPILE,
                    feedback_msg=simple_reason
                )
            
            self.patch_generator.patch_cache.add_patch(
                                                patch_hash=patch_hash, 
                                                raw_patch=self.raw_patch_attempt, 
                                                patch_attempt=self.patch_attempt, 
                                                root_cause_report_id=self.root_cause_report_id
                                                )
            self.patch_generator.patch_cache.set_action(patch_hash, cached_action)
            # =============================

            if self.programmer_compile_attempt_number <= Config.max_programmer_attempts_compile:
                self.programmer_guy.set_feedback(
                                            failure=FailureCodes.PATCHED_CODE_DOES_NOT_COMPILE, 
                                            feedback=simple_reason,
                                            extra_feedback=''
                                            )
            else:
                logger.info('✋🏼 Maximum number of attempts for this programmerGuy (patch_state: no-compile)!\n')
                # Stop feedback loop
                self.patch_state = 'stop'

        except PatchedCodeDoesNotPassBuildPass as e:
            logger.info('❌ Patched code does not pass the build pass!\n')

            self.patch_state = 'no-build-pass'
            self.programmer_total_attempts += 1
            self.programmer_compile_attempt_number += 1
            self.programmer_crash_attempt_number = 0
            self.programmer_tests_attempt_number = 0

            simple_reason = "The program does not pass the build pass after applying the patch! This means that you directly change the code of a harness, or code related to it!\n"
            simple_reason += "In other words, the program is not behaving the same way as before the patch, and this is NOT ALLOWED.\n"
            simple_reason += f"You can access the logs of the build pass process to see what went wrong at the following path: {e.stderr_log}\n\n"
            simple_reason += f"In particular, the log at {e.stderr_log} contains the stderr and stdout of the build pass process.\n"
            simple_reason += "Keep in mind: the error might be at the end of these logs, so make sure to scroll down if you are not sure what went wrong.\n"
            simple_reason += "Please adjust the proposed patch to resolve the build pass error.\n"

            # =============================
            # 💾 PatchCache management 
            # =============================
            # This is failed patch, we now store the response for this patch in patch_cache
            patch_hash = hashlib.sha256(str(self.patch_attempt).encode()).hexdigest()
            logger.info('   💾 Caching the patch attempt: %s\n', patch_hash)
            
            # NOTE: the error logs are still available (we are creating it with delete=False)
            cached_action = self.patch_generator.patch_cache.make_cached_action(
                    logger_msg=f'❌🔄 Patched code does not pass build pass!\n',
                    failure_code=FailureCodes.PATCHED_CODE_DOES_NOT_PASS_BUILD_PASS,
                    feedback_msg=simple_reason
                )
            
            self.patch_generator.patch_cache.add_patch(
                                                patch_hash=patch_hash, 
                                                raw_patch=self.raw_patch_attempt, 
                                                patch_attempt=self.patch_attempt, 
                                                root_cause_report_id=self.root_cause_report_id
                                                )
            self.patch_generator.patch_cache.set_action(patch_hash, cached_action)
            # =============================

            if self.programmer_compile_attempt_number <= Config.max_programmer_attempts_compile:
                self.programmer_guy.set_feedback(
                                            failure=FailureCodes.PATCHED_CODE_DOES_NOT_PASS_BUILD_PASS, 
                                            feedback=simple_reason,
                                            extra_feedback=''
                                            )
            else:
                logger.info('✋🏼 Maximum number of attempts for this programmerGuy (patch_state: no-build-pass)!\n')
                # Stop feedback loop
                self.patch_state = 'stop'

        except PatchedCodeHangs as e:
            logger.info('❌ Patched code hangs!\n')

            self.patch_state = 'patch-hangs (crash)'
            self.programmer_total_attempts += 1
            self.programmer_compile_attempt_number = 0
            self.programmer_crash_attempt_number += 1
            self.programmer_tests_attempt_number = 0

            if not e.new_hang:
                num_crashing_inputs_passed = e.num_passed
                if num_crashing_inputs_passed == 0:
                    simple_reason = "The program builded correctly but the execution hangs when trying the first crashing input! (we stopped testing after the first one)\n"
                    simple_reason += "This means that the new patch did not properly fix the issue.\n"
                    simple_reason += f"You can access the execution logs at the following path: {e.stderr_log}\n\n"
                    simple_reason += f"In particular, the log at {e.stderr_log} contains the stderr and stdout of the process execution.\n"
                    simple_reason += "Keep in mind: the error might be at the end of these logs, so make sure to scroll down if you are not sure what went wrong.\n"
                    simple_reason += "Please adjust the proposed patch to guarantee the termination of the program!\n"
                else:
                    simple_reason = f"The program builded correctly and does not crash when using {num_crashing_inputs_passed} crashing inputs!\n"
                    simple_reason += "However, the execution hangs when trying the next crashing input!\n"
                    simple_reason += "This means that the new patch did not properly fix the issue.\n"
                    simple_reason += f"You can access the execution logs at the following path: {e.stderr_log}\n\n"
                    simple_reason += f"In particular, the log at {e.stderr_log} contains the stderr and stdout of the process execution.\n"
                    simple_reason += "Keep in mind: the error might be at the end of these logs, so make sure to scroll down if you are not sure what went wrong.\n"
                    simple_reason += "Please adjust the proposed patch to guarantee the termination of the program!\n"
            else:
                simple_reason = "The program builded correctly and does not crash or hang for the first given crashing input!\n"
                simple_reason += "However, the execution hangs when trying a new similar crashing input!\n"
                simple_reason += "This means that the proposed patch did not properly fix the issue.\n"
                simple_reason += f"You can access the execution logs at the following path: {e.stderr_log}\n"
            # =============================
            # 💾 PatchCache management 
            # =============================
            # This is failed patch, we now store the response for this patch in patch_cache
            patch_hash = hashlib.sha256(str(self.patch_attempt).encode()).hexdigest()
            logger.info('   💾 Caching the patch attempt: %s\n', patch_hash)
            
            # NOTE: the error logs are still available (we are creating it with delete=False)
            cached_action = self.patch_generator.patch_cache.make_cached_action(
                    logger_msg=f'❌🔄 Patched code hangs!\n',
                    failure_code=FailureCodes.PATCHED_CODE_HANGS,
                    feedback_msg=simple_reason
                )
            
            self.patch_generator.patch_cache.add_patch(
                                                patch_hash=patch_hash, 
                                                raw_patch=self.raw_patch_attempt, 
                                                patch_attempt=self.patch_attempt, 
                                                root_cause_report_id=self.root_cause_report_id
                                                )
            self.patch_generator.patch_cache.set_action(patch_hash, cached_action)
            # =============================

            # NOTE: for now, we are counting a hang as a crash.
            if self.programmer_crash_attempt_number <= Config.max_programmer_attempts_crash:
                self.programmer_guy.set_feedback(
                                            failure=FailureCodes.PATCHED_CODE_HANGS, 
                                            feedback=simple_reason,
                                            extra_feedback=''
                                            )
            else:
                logger.info('✋🏼 Maximum number of attempts for this programmerGuy (patch_state: patch-hangs)!\n')
                # Stop feedback loop
                self.patch_state = 'stop'

        except PatchedCodeStillCrashes as e:
            logger.info('❌ Patched code still crashes!\n')

            self.patch_state = 'still-crash'
            self.programmer_total_attempts += 1
            self.programmer_compile_attempt_number = 0
            self.programmer_crash_attempt_number += 1
            self.programmer_tests_attempt_number = 0

            simple_reason = ""
            if not e.new_crash:
                num_crashing_inputs_passed = e.num_passed
                if num_crashing_inputs_passed == 0:
                    simple_reason = "The program builded correctly but the program crashes when trying the very first crashing input! (we stopped testing after the first one)\n"
                    simple_reason += "This means that the patch did not properly address the original vulnerability.\n"
                    simple_reason += "You must improve the patch to correctly address the vulnerability!\n"
                else:
                    simple_reason = f"The program builded correctly and does not crash when using {num_crashing_inputs_passed} crashing inputs!\n"
                    simple_reason += "However, the execution crashed when trying the next crashing input!\n"
                    simple_reason += "This means that the new patch did not properly fix the issue.\n"
                    simple_reason += "This means that the patch did not properly address the original vulnerability.\n"
                    simple_reason += "You must improve the patch to correctly address the vulnerability!\n"
                simple_reason += f"\nCRASH REPORT: '''\n{e.crash_report}\n'''"
            else:
                simple_reason = "The program builded correctly and does not crash or hang for the first given crashing input!\n"
                simple_reason += "However, the execution crashes when trying a new similar crashing input!\n"
                simple_reason += "This means that the proposed patch did not properly fix the issue.\n"
                simple_reason += f"\nCRASH REPORT: '''\n{e.crash_report}\n'''"

            # =============================
            # 💾 PatchCache management 
            # =============================
            # This is failed patch, we now store the response for this patch in patch_cache
            patch_hash = hashlib.sha256(str(self.patch_attempt).encode()).hexdigest()
            logger.info('   💾 Caching the patch attempt: %s\n', patch_hash)
            
            # NOTE: the error logs are still available (we are creating it with delete=False)
            cached_action = self.patch_generator.patch_cache.make_cached_action(
                    logger_msg=f'❌🔄 Patched code still crashes!\n',
                    failure_code=FailureCodes.PATCHED_CODE_STILL_CRASHES,
                    feedback_msg=simple_reason
                )
            
            self.patch_generator.patch_cache.add_patch(
                                                patch_hash=patch_hash, 
                                                raw_patch=self.raw_patch_attempt, 
                                                patch_attempt=self.patch_attempt, 
                                                root_cause_report_id=self.root_cause_report_id
                                                )
            self.patch_generator.patch_cache.set_action(patch_hash, cached_action)
            # =============================

            if self.programmer_crash_attempt_number <= Config.max_programmer_attempts_crash:
                self.programmer_guy.set_feedback(
                                            failure=FailureCodes.PATCHED_CODE_STILL_CRASHES, 
                                            feedback=simple_reason,
                                            extra_feedback=''
                                            )
            else:
                logger.info('✋🏼 Maximum number of attempts for this programmerGuy (patch_state: still-crash)!\n')
                # Stop feedback loop
                self.patch_state = 'stop'

        except PatchedCodeDoesNotPassTests as e:
            logger.info('❌ Patched code does not pass the tests!\n')
            
            self.patch_state = 'no-tests'
            self.programmer_total_attempts += 1
            self.programmer_compile_attempt_number = 0
            self.programmer_crash_attempt_number = 0
            self.programmer_tests_attempt_number += 1 

            simple_reason = "The program does not pass the unit tests after applying the patch!\n"
            simple_reason += "This means that the patch did fix the vulnerability, but broke some other functionalities.\n"
            simple_reason += "You are close! Please adjust the patch to fix the vulnerability without breaking the other functionalities and we are done!\n"
            simple_reason += f"You can access the logs of the unit testing process to see what went wrong at the following path: {e.stderr_log}"
            simple_reason += f"In particular, the log at {e.stderr_log} contains the stderr and stdout of the unit testing process.\n"
            simple_reason += "Keep in mind: the error might be at the end of these logs, so make sure to scroll down if you are not sure what went wrong.\n"

            # =============================
            # 💾 PatchCache management 
            # =============================
            # This is failed patch, we now store the response for this patch in patch_cache
            patch_hash = hashlib.sha256(str(self.patch_attempt).encode()).hexdigest()
            logger.info('   💾 Caching the patch attempt: %s\n', patch_hash)
            
            cached_action = self.patch_generator.patch_cache.make_cached_action(
                    logger_msg=f'❌🔄 Patched code does not pass the tests!\n',
                    failure_code=FailureCodes.PATCHED_CODE_DOES_NOT_PASS_TESTS,
                    feedback_msg=simple_reason
                )
            
            self.patch_generator.patch_cache.add_patch(
                                                patch_hash=patch_hash, 
                                                raw_patch=self.raw_patch_attempt, 
                                                patch_attempt=self.patch_attempt, 
                                                root_cause_report_id=self.root_cause_report_id
                                                )
            self.patch_generator.patch_cache.set_action(patch_hash, cached_action)
            # =============================

            if self.programmer_tests_attempt_number <= Config.max_programmer_attempts_tests:
                self.programmer_guy.set_feedback(
                                            failure=FailureCodes.PATCHED_CODE_DOES_NOT_PASS_TESTS, 
                                            feedback=simple_reason,
                                            extra_feedback=''
                                            )
            else:
                logger.info('✋🏼 Maximum number of attempts for this programmerGuy (patch_state: no-tests)!\n')
                # Stop feedback loop
                self.patch_state = 'stop'
        
        except PatchedCodeDoesNotPassCritic as e:
            logger.info('❌ Patched code does not pass the critic!\n')
            
            self.patch_state = 'no-critic'
            self.programmer_total_attempts += 1
            self.programmer_compile_attempt_number = 0
            self.programmer_crash_attempt_number = 0
            self.programmer_tests_attempt_number = 0

            simple_reason = "The patch does not pass the code reviewer check!\n"
            simple_reason += "This means that the patch did not address the vulnerability effienctly.\n"
            # simple_reason += "You are close! Please adjust the patch to fix the vulnerability based on the feedback and we are done!\n"
            simple_reason += f"You MUST improve the patch according to the following feedback:\n'''\n{e.feedback}\n'''"

            # =============================
            # 💾 PatchCache management 
            # =============================
            # This is failed patch, we now store the response for this patch in patch_cache
            patch_hash = hashlib.sha256(str(self.patch_attempt).encode()).hexdigest()
            logger.info('   💾 Caching the patch attempt: %s\n', patch_hash)
            
            cached_action = self.patch_generator.patch_cache.make_cached_action(
                    logger_msg=f'❌🔄 Patched code does not pass the critic!\n',
                    failure_code=FailureCodes.PATCHED_CODE_DOES_NOT_PASS_CRITIC,
                    feedback_msg=simple_reason
                )
            
            self.patch_generator.patch_cache.add_patch(
                                                patch_hash=patch_hash, 
                                                raw_patch=self.raw_patch_attempt, 
                                                patch_attempt=self.patch_attempt, 
                                                root_cause_report_id=self.root_cause_report_id
                                                )
            self.patch_generator.patch_cache.set_action(patch_hash, cached_action)
            # =============================

            self.programmer_guy.set_feedback(
                                        failure=FailureCodes.PATCHED_CODE_DOES_NOT_PASS_CRITIC, 
                                        feedback=simple_reason,
                                        extra_feedback=''
                                        )
        
        except Exception as e:
            logger.info('🤡 Unexpected error during verification: %s\n', e)
            # This is an error to fix
            assert False
    
    def save(self, patched_cp=None):
        logger.info('✅ Patch from root-cause %s verified successfully!\n', self.root_cause_report_id)
        
        # ==================
        # 🖨️ SAVE THE PATCH
        # ==================
        logger.info('Git diff:\n %s', self.git_diff)
        self.patch_name = hashlib.md5(os.urandom(16)).hexdigest()
        patch_filename = Path(self.patcherq.kwargs['patch_output_path']) / self.patch_name
        os.makedirs(Path(self.patcherq.kwargs['patch_output_path']), exist_ok=True)
        assert patch_filename is not None

        total_cost = agentlib.lib.agents.agent.global_event_dumper.total_cost_per_million / 1_000_000

        # ⬆️ Now we upload the patch to the analysis graph
        if Config.patcherq_mode == PatcherqMode.PATCH:

            message = "Amazing, your patch fixed the program! Can you create an executive summary of the patch you just created?\n"
            message += "You should mention the files and the functions you changed and how you changed them. The report should be concise, containing ALL the critical information needed to understand the patch, and should be written in passive form.\n"
            message += "DO NOT USE MARKDOWN SYNTAX, JUST PLAIN TEXT."

            self.programmer_guy.set_human_msg(message)
            summary = ''
            try:
                res = self.programmer_guy.invoke()
                summary = res.chat_messages[-1].content
            except Exception as e:
                # NOTE: this is not a fatal error, we can still upload the patch without the summary
                logger.info(' 🥹 Error while generating the patch summary: %s\n. This is not FATAL, skipping it...', e)

            analysis_graph_crash_reports.GeneratedPatch.upload_patch(
                                                                    pdt_project_id=self.patcherq.kwargs['project_id'],
                                                                    patch_pdt_id=self.patch_name,
                                                                    diff=self.git_diff, poi_report_id=self.patcherq.poi_report_meta.crash_report_id,
                                                                    mitigated_poi_report_ids=[self.patcherq.poi_report_meta.crash_report_id],
                                                                    non_mitigated_poi_report_ids=[],
                                                                    refined_patch_id=None,
                                                                    patcher_name='patcherQ',
                                                                    summary=summary,
                                                                    total_cost=total_cost,
                                                                    build_request_id=self.build_request_id
                                                                    )
        elif Config.patcherq_mode == PatcherqMode.REFINE:

            message = "Amazing, your patch fixed the program! Can you create an executive summary of the patch you just created?\n"
            message += "You should mention the files and the functions you changed and how you changed them. The report should be concise, containing ALL the critical information needed to understand the patch, and should be written in passive form.\n"
            message += "DO NOT USE MARKDOWN SYNTAX, JUST PLAIN TEXT."

            summary = ''
            try:
                self.programmer_guy.set_human_msg(message)
                res = self.programmer_guy.invoke()
                summary = res.chat_messages[-1].content
            except Exception as e:
                # NOTE: this is not a fatal error, we can still upload the patch without the summary
                logger.info(' 🥹 Error while generating the patch summary: %s\n. This is not FATAL, skipping it...', e)

            mitigated_poi_report_ids = [self.patcherq.poi_report_meta.crash_report_id]
            analysis_graph_crash_reports.GeneratedPatch.upload_patch(
                                                                    pdt_project_id=self.patcherq.kwargs['project_id'],
                                                                    patch_pdt_id=self.patch_name,
                                                                    diff=self.git_diff, poi_report_id=self.patcherq.poi_report_meta.crash_report_id,
                                                                    mitigated_poi_report_ids=mitigated_poi_report_ids,
                                                                    non_mitigated_poi_report_ids=[],
                                                                    refined_patch_id=self.patcherq.failing_patch.key,
                                                                    patcher_name='patcherQ',
                                                                    summary=summary,
                                                                    total_cost=total_cost,
                                                                    build_request_id=self.build_request_id
                                                                    )
        else:

            message = "Amazing, your patch fixed the program! Can you create an executive summary of the patch you just created?\n"
            message += "You should mention the files and the functions you changed and how you changed them. The report should be concise, containing ALL the critical information needed to understand the patch, and should be written in passive form.\n"
            message += "DO NOT USE MARKDOWN SYNTAX, JUST PLAIN TEXT."

            summary = ''
            try:
                self.programmer_guy.set_human_msg(message)
                res = self.programmer_guy.invoke()
                summary = res.chat_messages[-1].content
            except Exception as e:
                # NOTE: this is not a fatal error, we can still upload the patch without the summary
                logger.info(' 🥹 Error while generating the patch summary: %s\n. This is not FATAL, skipping it...', e)
            
            try:
                analysis_graph_crash_reports.GeneratedPatch.upload_sarif_patch(
                                                                                pdt_project_id=self.patcherq.kwargs['project_id'],
                                                                                patch_pdt_id=self.patch_name,
                                                                                diff=self.git_diff,
                                                                                sarif_report_id=self.patcherq.sarif_report_id,
                                                                                patcher_name='patcherQ',
                                                                                summary=summary,
                                                                                total_cost=total_cost,
                                                                                build_request_id=self.build_request_id
                                                                                )
            except Exception as e:
                logger.info(' 💩 Error while uploading the SARIF patch to the analysis graph: %s\n. This is not FATAL, skipping it...', e)

        # Writing the patch metadata to trigger patch patrol!
        patch_meta_filename = Path(self.patcherq.kwargs['patch_metadata_output_path']) / self.patch_name
        os.makedirs(Path(self.patcherq.kwargs['patch_metadata_output_path']), exist_ok=True)
        assert patch_meta_filename is not None
        logger.info(' - Generating patch metadata at %s\n', patch_meta_filename)
        
        with open(patch_meta_filename, 'w') as f:
            if Config.patcherq_mode == PatcherqMode.SARIF:
                patch_metadata: PatchMetaData = PatchMetaData(
                        patcher_name='patcherQ',
                        total_cost=total_cost,
                        pdt_project_id=self.patcherq.kwargs['project_id'],
                        pdt_project_name=self.patcherq.project_name,
                        build_request_id=self.build_request_id
                    )
            else:
                patch_metadata: PatchMetaData = PatchMetaData(
                        patcher_name='patcherQ',
                        total_cost=total_cost,
                        poi_report_id=self.patcherq.poi_report_meta.crash_report_id,
                        pdt_project_name=self.patcherq.poi_report_meta.project_name,
                        pdt_project_id=self.patcherq.poi_report_meta.project_id,
                        pdt_harness_info_id=self.patcherq.poi_report_meta.harness_info_id,
                        build_request_id=self.build_request_id
                    )
            yaml.safe_dump(patch_metadata.model_dump(), f, default_flow_style=False, sort_keys=False)

        # Emit patch! 👑
        ################
        logger.info(' - Saving patch at %s\n', patch_filename)
        with open(patch_filename, 'w') as f:
            f.write(self.git_diff)

        self.successful_patch_attempts[self.root_cause_report_id] = (patch_filename, self.programmer_total_attempts, self.root_cause_report, self.git_diff)
        
        functions_attempted_to_patch = set()
        if self.patcherq.is_permanence_on and Config.patcherq_mode != PatcherqMode.SARIF:
            try:
                # Save the patch in libpermanence!
                self.patcherq.permanence_client.successful_patch(self.patcherq.cp.project_name, self.patcherq.poi_report_meta.cp_harness_name, self.patcherq.poi_report, self.git_diff, self.functions_in_patch)
                logger.info(' 💾 Saved successful patch to libpermanence!')
            except Exception as e:
                logger.info('Error while saving the patch in libpermanence: %s\n. This is not FATAL, skipping it...', e)

        if Config.emit_bypass_request and Config.patcherq_mode != PatcherqMode.SARIF:
            try:
                patch_id = hashlib.sha256(self.git_diff.encode()).hexdigest()
                # We need to generate the bypass request for DiscoveryGuy
                message = "Amazing, your patch fixed the program! Can you create an executive summary of the patch you just created?\n"
                message += "You should mention the files and the functions you changed and how you changed them. The report should be concise, containing ALL the critical information needed to understand the patch, and should be written in passive form.\n"
                message += "DO NOT USE MARKDOWN SYNTAX, JUST PLAIN TEXT."

                self.programmer_guy.set_human_msg(message)
                summary = ''
                try:
                    res = self.programmer_guy.invoke()
                    summary = res.chat_messages[-1].content
                except Exception as e:
                    # NOTE: this is not a fatal error, we can still upload the patch without the summary
                    logger.info(' 🥹 Error while generating the summary for the bypass request: %s\n. This is not FATAL, skipping it...', e)

                # NOTE: this is the same ID that is used to identify the patch in the analysis graph
                bypass_request = PatchBypassRequestMeta(
                    project_id=self.patcherq.kwargs['project_id'],
                    harness_id=self.patcherq.poi_report_meta.harness_info_id,
                    sanitizer_name=self.patcherq.kwargs['sanitizer_to_build_with'],
                    patch_id=patch_id,
                    patch_description=summary,
                    mitigated_poi_report_id=self.patcherq.poi_report_meta.crash_report_id,
                    patcher_name='patcherQ',
                    sarif_id=None,
                    build_request_id=''
                )
                # Write the bypass request to a file
                logger.info(f" ⛓️‍💥🤔 Creating bypass request at {self.patcherq.kwargs['bypass_request_output_path']}")
                bypass_request_at = os.path.join(self.patcherq.kwargs['bypass_request_output_path'], patch_id)
                with open(bypass_request_at, 'w') as f:
                    yaml.safe_dump(bypass_request.model_dump(), f, default_flow_style=False, sort_keys=False)
            except Exception as e:
                logger.info(' 😶‍🌫️ Error while generating the bypass request. This is not FATAL, skipping it...')

        if Config.emit_patched_artifacts:
            patch_id = hashlib.sha256(self.git_diff.encode()).hexdigest()
            logger.info(f" 💾 Saving patched artifacts at {self.patcherq.patched_artifacts_out}")
            self.patcherq.patched_artifacts_out.upload(patch_id, patched_cp.artifacts_dir)

    def make_sarif(self, successful_patch_attempts: dict):
        # We dont pQ to crash ever when doing sarif gen
        try:
            for root_cause_report_id in successful_patch_attempts:
                
                sarif_guy = SARIFGuy(
                                    func_resolver=self.patcherq.func_resolver,
                                    project_name=self.patcherq.project_name,
                                    poi_report=self.patcherq.poi_report,
                                    root_cause_report=str(successful_patch_attempts[root_cause_report_id][2]),
                                    patch=str(successful_patch_attempts[root_cause_report_id][3])
                                    )
                try:
                    res = sarif_guy.invoke()
                    logger.info(' - SARIF key generation successful!\n%s\n', res.value)
                except LLMApiBudgetExceededError:
                    logger.critical(' 😭 LLM API budget exceeded for %s!', sarif_guy.__LLM_MODEL__)
                    logger.critical('   - NOTE: it is fine to let this exception go through, we will just skip the SARIF generation for this patch.\n')
                    break

                sarif_keys = res.value
                
                flow = []
                # If start line is not a digit, we omit the region section of sarif location
                # If filepaath is incorrect, we omit the entire location entry for that file
                for flow_item in sarif_keys['FLOW']:
                    cleaned_flow_item = []
                    functions_info = list(self.patcherq.func_resolver.find_by_filename(flow_item[0]))
                    if len(functions_info) != 0:
                        functions_in_scope = []
                        for func_key in functions_info:
                            func_index = self.patcherq.func_resolver.get(func_key)
                            if func_index.focus_repo_relative_path:
                                functions_in_scope.append(func_key)
                                # We can just stop here since we found at least one function in scope in this file
                                break

                        # NOTE: the file_path is relative to the focused repo.
                        cleaned_flow_item.append(str(self.patcherq.func_resolver.get(functions_in_scope[0]).focus_repo_relative_path).lstrip("/"))
                    else:
                        continue
                    if not flow_item[1].isdigit():
                        cleaned_flow_item.append(0)
                    else:
                        cleaned_flow_item.append(flow_item[1])
                    flow.append(cleaned_flow_item)  
                sarif_keys['FLOW'] = flow

                sarif = sarif_guy.generate_sarif(sarif_keys)
                if not sarif_guy.validate_sarif(sarif):
                    logger.info('🤡 SARIF generation failed! The SARIF is not valid, skipping it...\n')
                    continue
                
                sarif_filename = Path(self.patcherq.kwargs['sarif_output_path']) / self.patch_name
                os.makedirs(Path(self.patcherq.kwargs['sarif_output_path']), exist_ok=True)
                assert sarif_filename is not None
                logger.info(' - Saving SARIF at %s\n', sarif_filename)
                with open(sarif_filename, 'w') as f:
                    f.write(sarif)
        except Exception as e:
            logger.info('Error while generating SARIF: %s\n. This is not FATAL, skipping it...', e)
