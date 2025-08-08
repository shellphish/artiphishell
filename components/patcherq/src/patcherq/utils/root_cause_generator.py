import yaml
import logging
import time
import random

from datetime import datetime, timedelta
from typing import Optional

from ..config import Config, PatcherqMode
from ..agents import TriageGuy
from ..models import RootCauseReport

from agentlib.lib.common import LLMApiBudgetExceededError, LLMApiRateLimitError
from shellphish_crs_utils.telemetry import PatcherQTelemetry, EVENTS
from shellphish_crs_utils.models.crs_reports import RootCauseReport as DyvaRootCauseReport
from shellphish_crs_utils.sarif_resolver import SarifResolver

from ..agents.exceptions import MaxToolCallsExceeded

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class RootCauseGenerator:
    def __init__(self, patcherq, function_resolver = None):
        self.patcherq = patcherq
        
        # NOTE: some guarding variable
        self.how_many_naps = 0
        
        # Make generator
        self.generators = {}
        
        if Config.patcherq_mode == PatcherqMode.SARIF:
            self.generators['sarif'] = {'func': self.sarif, 'args': [function_resolver], 'generated': False, 'error':''}
        
        elif Config.patcherq_mode == PatcherqMode.PATCH:
            if Config.use_dyva_report and 'dyva_report' in self.patcherq.kwargs and self.patcherq.kwargs['dyva_report']:
                self.generators['dyva'] = {'func': self.dyva, 'args': [], 'generated': False, 'error':''}
            for llm_idx, llm_name in enumerate(Config.triage_llms):
                self.generators[f'triage_{llm_name}_{llm_idx}'] = {'func': self.triage, 'args': [llm_name], 'generated': False, 'error':''}
        
        elif Config.patcherq_mode == PatcherqMode.REFINE:
            # NOTE: if dyva supports refinement, we can use that.
            for llm_idx, llm_name in enumerate(Config.triage_llms):
                self.generators[f'triage_{llm_name}_{llm_idx}'] = {'func': self.triage_refine, 'args': [llm_name], 'generated': False, 'error':''}
        else:
            raise ValueError(f"Unknown patcherq mode: {Config.patcherq_mode}. Please use one of the following: {PatcherqMode.__members__.keys()}")
    
    def reports(self):
        # NOTE: this function can be called multiple times in case of LLM budget exceptions.
        # So we need to keep track of the reports we have already generated.
        
        # NOTE: if we have generated all the possible available reports, we must quit.
        if not self.check_missing_reports():
            logger.info('😭 All reports generated! No more root cause reports to generate. Bye 👋🏼')
            exit(0)

        for gen_type in self.generators:
            
            if self.generators[gen_type]['generated']:
                # If we have already generated a report for this llm, we will not generate it again.
                continue

            if self.generators[gen_type]['args']:
                report = self.generators[gen_type]['func'](*self.generators[gen_type]['args'])
            else:
                report = self.generators[gen_type]['func']()
            
            if report == None and gen_type == "dyva":
                # NOTE: for dyva, a None report means that we are not using it.
                self.generators[gen_type]['generated'] = True

            # Check if we have a valid report from an LLM.
            if report == None:
                # Something bad happened. Probably out of budget.
                # We are marking this as False and trying again later.
                self.generators[gen_type]['generated'] = False
            else:
                # This means we got a valid root cause report from an LLM.
                self.generators[gen_type]['generated'] = True

            yield report

    def check_missing_reports(self) -> bool:
        # Check if we have generated all the reports we need.
        # If not, we will take a nap and wait for the next budget tick.
        for gen_type in self.generators:
            if self.generators[gen_type]['generated'] == False:
                return True
        return False

    def take_a_nap(self) -> None:
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

    def sarif(self, function_resolver) -> Optional[RootCauseReport]:
        report_text = None
        try:
            sarif_path = self.patcherq.kwargs['sarif_input_path']

            resolver = SarifResolver(sarif_path, function_resolver)

            results = resolver.get_results()
            
            if not results or len(results) == 0:
                logger.warning("🤷🏻‍♂️ No SARIF results in %s. We are done here! Bye 👋🏼", sarif_path)
                # NOTE: this is a little dramatic, but it is better to just leave ASAP the pod spot.
                import sys; sys.exit(0)
            
            issue_ticket = results[0].rule_id
            
            lines = []

            for res in results:
                if res.message:
                    lines.append(f"Message: {res.message}")

                if res.locations:
                    lines.append("Locations:")
                    for loc in res.locations:
                        lines.append(f"- File: {loc.file}, Function: {loc.func}, Line: {loc.line}")

                if res.codeflows:
                    lines.append("Code Flows:")
                    for cf in res.codeflows:
                        lines.append(f"- CodeFlow #{cf.code_flow_id}:")
                        for step in cf.locations:
                            lines.append(f"    • File: {step.file}, Function: {step.func}, Line: {step.line}")

            report_text = "\n".join(lines)
            report = "<Root_Cause_Report>\n" \
                    f'#Project Name\n{self.patcherq.project_name}\n' \
                    f'#Project Language\n{self.patcherq.project_language}\n' \
                    f'#Security Issue:\n{issue_ticket}\n' \
                    f'#Root-Cause:\n{report_text}\n' \
                    "<\Root_Cause_Report>\n"
            print(report)
            return report

        except Exception as e:
            logger.error("Error generating SARIF-based root cause: %s", e, exc_info=True)
            return None

    def dyva(self):
        report = None
        try:
            dyva_report = DyvaRootCauseReport.model_validate(yaml.safe_load(open(self.patcherq.kwargs['dyva_report'], 'r')))
            
            if dyva_report.errored:
                # If the dyva report has an error, we will not use it.
                logger.error("Dyva report has an error: %s. Not using it.", dyva_report.description)
                return report
            else:
                # Use dyva report
                logger.info("We are using dyva report as a first root-cause report!")
                assert dyva_report != None
                if Config.use_dyva_suggestions:
                    report = "<Root_Cause_Report>\n" \
                            f'# Project Name\n{self.patcherq.project_name}\n\n' \
                            f'# Project Language\n{self.patcherq.project_language}\n\n' \
                            f'{self.patcherq.issue_ticket}\n\n' \
                            f'# Root-Cause and Proposed Fixes\n{yaml.dump(dyva_report.model_dump())}\n' \
                            "<\Root_Cause_Report>\n"
                else:
                    report = "<Root_Cause_Report>\n" \
                            f'# Project Name\n{self.patcherq.project_name}\n\n' \
                            f'# Project Language\n{self.patcherq.project_language}\n\n' \
                            f'{self.patcherq.issue_ticket}\n\n' \
                            f'# Root-Cause\n{yaml.dump(dyva_report.model_dump(exclude={"patches", "errored"}))}\n' \
                            "<\Root_Cause_Report>\n"
        except Exception as e:
            logger.error("Error loading dyva report: %s. Saasthone is a clown!", e, exc_info=True)
        
        return report

    def triage(self, llm: str):
        report = None

        logger.info('🕵🏻 TriageGuy Running with %s', llm)
        triage_guy = TriageGuy(
                                init_context=str(self.patcherq.initial_context_report), 
                                project_language=self.patcherq.project_language, 
                                with_invariants=False,
                                with_lang_server=Config.use_lang_server,
                                with_codeql_server=Config.use_codeql_server,
                            )
        triage_guy.__LLM_MODEL__ = llm
        triage_guy.llm  = triage_guy.get_llm_by_name(
                                                     llm, 
                                                     **triage_guy.__LLM_ARGS__,
                                                     raise_on_budget_exception=triage_guy.__RAISE_ON_BUDGET_EXCEPTION__,
                                                     raise_on_rate_limit_exception=triage_guy.__RAISE_ON_RATE_LIMIT_EXCEPTION__
                                                     )
        
        # The tool calls guard need to be cleaned every time 
        # we instantiate a new agent (ugly...)
        self.patcherq.peek_src.clean_tool_call_history()
        self.patcherq.peek_logs.clean_tool_call_history()
        
        try:
            res = triage_guy.invoke()
            # NOTE: if invoke succeeds, we can reset the nap counter
            self.how_many_naps = 0
        except MaxToolCallsExceeded:
            logger.critical(f'😭 Max tool calls exceeded for TriageGuy with model {llm}!')
            # NOTE: for now let's give up HARD on this.
            # NOTE: we are failing hard because I suspect that when we hit this, the crash
            #       report is SO bad that every LLM is gonna fail and waste a ton of resources.
            import sys; sys.exit(1)
        except LLMApiBudgetExceededError:
            logger.critical(f'😭 LLM API budget exceeded for TriageGuy with model {llm}!')
            # NOTE: for now we return an empty report, the logic of handling budget exceptions
            #       is handled in the main loop (main.py)
            return report
        except LLMApiRateLimitError:
            logger.critical(f'😭 LLM API rate limit exceeded for TriageGuy with model {llm}!')
            # NOTE: for now we return an empty report, the logic of handling budget exceptions
            #       is handled in the main loop (main.py)
            return report
        except Exception as e:
            logger.error(f'🤡 Error invoking TriageGuy with model {llm}: {e}')
            # NOTE: we will return an empty report, the logic of handling budget exceptions
            #       is handled in the main loop (main.py)
            return report

        report = res.value

        # convert this into a RootCauseReport 
        report = RootCauseReport(
                                project_name=self.patcherq.project_name,
                                project_language=self.patcherq.project_language,
                                issueTicket=self.patcherq.issue_ticket,
                                root_cause_report=report
                                )
        return report

    def triage_refine(self, llm: str):
        report = None

        logger.info(f'🕵🏻 TriageGuy Running with {llm}')
        triage_guy = TriageGuy(
                                init_context=str(self.patcherq.initial_context_report), 
                                project_language=self.patcherq.project_language, 
                                with_invariants=False,
                                with_lang_server=Config.use_lang_server,
                                with_codeql_server=Config.use_codeql_server,
                                refine_this=self.patcherq.failing_patch,
                                failed_functionality=self.patcherq.failed_functionality
                            )
        triage_guy.__LLM_MODEL__ = llm

        triage_guy.llm  = triage_guy.get_llm_by_name(
                                                     llm, 
                                                     **triage_guy.__LLM_ARGS__,
                                                     raise_on_budget_exception=triage_guy.__RAISE_ON_BUDGET_EXCEPTION__,
                                                     raise_on_rate_limit_exception=triage_guy.__RAISE_ON_RATE_LIMIT_EXCEPTION__
                                                    )
        
        # The tool calls guard need to be cleaned every time 
        # we instantiate a new agent (ugly...)
        self.patcherq.peek_src.clean_tool_call_history()
        self.patcherq.peek_logs.clean_tool_call_history()
        
        try:
            res = triage_guy.invoke()
        except LLMApiBudgetExceededError:
            logger.critical(f'😭 LLM API budget exceeded for TriageGuy with model {llm}!')
            return report
        except LLMApiRateLimitError:
            logger.critical(f'😭 LLM API rate limit exceeded for TriageGuy with model {llm}!')
            return report
        except MaxToolCallsExceeded:
            logger.critical(f'😭 Max tool calls exceeded for TriageGuy with model {llm}!')
            # NOTE: for now let's give up HARD on this.
            # NOTE: we are failing hard because I suspect that when we hit this, the crash
            #       report is SO bad that every LLM is gonna fail and waste a ton of resources.
            import sys; sys.exit(1)
        except Exception as e:
            logger.error(f'🤡 Error invoking TriageGuy with model {llm}: {e}')
            # NOTE: we will return an empty report, the logic of handling budget exceptions
            #       is handled in the main loop (main.py)
            return report

        report = res.value

        # convert this into a RootCauseReport 
        report = RootCauseReport(
                                project_name=self.patcherq.project_name,
                                project_language=self.patcherq.project_language,
                                issueTicket=self.patcherq.issue_ticket,
                                root_cause_report=report
                                )
        return report
