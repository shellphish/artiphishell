import os
import yaml
import logging
import agentlib
import time
import fnmatch

from neomodel import db
from pathlib import Path
from typing import Tuple, Set
from datetime import datetime, timedelta

from .config import Config
from .agents import IssueGuy
from .models import InitialContextReport
from .utils.supress import maybe_suppress_output

from agentlib.lib.common import LLMApiBudgetExceededError, LLMApiRateLimitError
from shellphish_crs_utils.models.crs_reports import POIReport
from shellphish_crs_utils.models.oss_fuzz import AugmentedProjectMetadata
from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject
from shellphish_crs_utils.function_resolver import LocalFunctionResolver, RemoteFunctionResolver, FUNCTION_INDEX_KEY
from permanence.client import PermanenceClient
from shellphish_crs_utils.sarif_resolver import SarifResolver

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class Helper:
    def setup_project(kwargs):

        with open(kwargs['project_yaml'], 'r') as f:
            project_yaml = AugmentedProjectMetadata.model_validate(yaml.safe_load(f))

        cp = OSSFuzzProject(
                            project_id = kwargs['project_id'],
                            oss_fuzz_project_path = Path(kwargs['target_root']),
                            augmented_metadata=project_yaml,
                            project_source = Path(kwargs['source_root']),
                            use_task_service = not Config.is_local_run
                            )

        if Config.is_local_run:
            print("[LOCAL_RUN] Building the builder and runner images...\n")
            with maybe_suppress_output():
                cp.build_builder_image()
                cp.build_runner_image()
            func_resolver = LocalFunctionResolver(kwargs['function_index'], kwargs['target_functions_jsons_dir'])
        else:
            logger.info(f"Initializing RemoteFunctionResolver with project_name={project_yaml.shellphish_project_name}, project_id={kwargs['project_id']}")
            func_resolver = RemoteFunctionResolver(project_yaml.shellphish_project_name, kwargs['project_id'])
            # Fallback
            if not func_resolver.is_ready():
                func_resolver = LocalFunctionResolver(kwargs['function_index'], kwargs['target_functions_jsons_dir'])
        
        if not Config.is_local_run and Config.is_permanence_on:
            is_permanence_on = True
            permanence_client = PermanenceClient(function_resolver=func_resolver)
        else:
            is_permanence_on = False
            permanence_client = None

        return cp, func_resolver, is_permanence_on, permanence_client

    @staticmethod
    def run_cypher_query(query: str, params: dict, resolve_objects: bool):
        attempts = 3
        for attempt in range(1, attempts + 1):
            try:
                results, columns = db.cypher_query(query=query, params=params, resolve_objects=resolve_objects)
                return results, columns
            except Exception as e:
                if attempt < attempts:
                    logger.warning(f"❓ Error: {e}, retrying... (Attempt {attempt}/{attempts})")
                    time.sleep(60)  # Wait for a minute before retrying
                else:
                    logger.error(f"❌ Error: {e}, failed after {attempts} attempts.")
                    return None, None
        return None, None

    def get_failing_patch_info(patch_key: str):
        query = f"""
        MATCH (p:GeneratedPatch) WHERE p.patch_key = $patch_key
        RETURN p
        """

        params = {
            "patch_key": patch_key,
        }
        results, columns = Helper.run_cypher_query(query=query, params=params, resolve_objects=True)
        return results
    
    def get_crashing_inputs_from_bucket(bucket_key: str, max_limit: int = 5):
        query = """
        MATCH (b:BucketNode)-[:CONTAIN_POV_REPORT]->(p:PoVReportNode)-[:HARNESS_INPUT]->(h:HarnessInputNode) 
        WHERE b.bucket_key = $bucket_key AND h.crashing = true
        RETURN h
        LIMIT $max_limit
        """
        params = {
            "bucket_key": bucket_key,
            "max_limit": max_limit,
        }

        results, columns = Helper.run_cypher_query(query=query, params=params, resolve_objects=True)
        return results
    
    def get_mitigated_pov_reports(patch_key: str):
        query = f"""
        MATCH (p:GeneratedPatch) WHERE p.patch_key = $patch_key
        MATCH (p)-[:MITIGATED_POV_REPORT]->(poi:PoVReportNode)
        RETURN poi
        """

        params = {
            "patch_key": patch_key,
        }

        results, columns = Helper.run_cypher_query(query=query, params=params, resolve_objects=True)

        return results
    
    def get_crashing_input_for(pov_report_key: str):
        query = f"""
        MATCH (p:PoVReportNode) WHERE p.key = $pov_report_key
        MATCH (p)-[:HARNESS_INPUT]->(input:HarnessInputNode)
        RETURN input 
        """

        params = {
            "pov_report_key": pov_report_key,
        }

        results, columns = Helper.run_cypher_query(query=query, params=params, resolve_objects=True)

        return results
    
    def get_crashing_input_with_id(crashing_input_id: str):
        query = f"""
        MATCH (h:HarnessInputNode) WHERE h.identifier = $crashing_input_id
        RETURN h
        """

        params = {
            "crashing_input_id": crashing_input_id,
        }

        results, columns = Helper.run_cypher_query(query=query, params=params, resolve_objects=True)

        return results

    def save_root_cause_reports(id: datetime, root_cause_reports: set):
        successful_patch_log_path = os.path.join("/shared/patcherq/stats/", f"successful_patches_{id}/")
        # Save all the root-causes reports
        for root_cause_report_id, root_cause_report in enumerate(root_cause_reports):
            with open(successful_patch_log_path + "/root_cause_report_" + str(root_cause_report_id), 'w') as f:
                yaml.safe_dump(str(root_cause_report), f)
        
    def save_successful_patch_attempts(id: datetime, successful_patch_attempts: dict):
        successful_patch_log_path = os.path.join("/shared/patcherq/stats/", f"successful_patches_{id}/")

        # Create the directory if it does not exist
        os.makedirs(successful_patch_log_path, exist_ok=True)
        assert os.path.exists(successful_patch_log_path), "Failed to create the directory for successful patches!"

        if len(successful_patch_attempts) > 0:
            logger.info(' 🥳 There are %d successful patch attempts\n', len(successful_patch_attempts))
            for root_cause_report_id in successful_patch_attempts:
                logger.info(' - %s\n', successful_patch_attempts[root_cause_report_id][0])
                successful_patch_log = os.path.join(successful_patch_log_path, "successful_patches.txt")
                
                # create the file
                if not os.path.exists(successful_patch_log):
                    with open(successful_patch_log, 'w') as f:
                        f.write("Successful Patches Attempts\n")
                        f.write("=========================\n")

                with open(successful_patch_log, 'a') as f:
                    f.write(f"{successful_patch_attempts[root_cause_report_id][0]} - {successful_patch_attempts[root_cause_report_id][1]}\n")
        else:
            logger.info(' 🤡 No successful patch attempts were made\n')

    def take_a_nap():
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

    def get_funcs_in_scope_sarif(patcherq) -> Set[FUNCTION_INDEX_KEY]:
        function_resolver = patcherq.func_resolver
        sarif_path = patcherq.kwargs['sarif_input_path']
        resolver = SarifResolver(sarif_path, function_resolver)
        results = resolver.get_results()
        funcs_in_scope = set()
        for res in results:
            if res.locations:
                for loc in res.locations:
                    funcs_in_scope.add(loc.keyindex)

            if res.codeflows:
                for cf in res.codeflows:
                    for step in cf.locations:
                        funcs_in_scope.add(step.keyindex)
        return funcs_in_scope

    def get_initial_context_report(patcherq):
        cp = patcherq.cp
        poi_report_path = patcherq.kwargs['poi_report']
        func_resolver = patcherq.func_resolver
        project_name = patcherq.project_name
        project_language = patcherq.project_language

        issue_guy_how_many_naps = 0

        # Initialize with files showing up in the POI report
        files_in_scope, funcs_in_scope = Helper.load_files_and_funcs_in_scope_from_poi(poi_report_path, cp, func_resolver)
        if len(files_in_scope):
            logger.info('Files in scope: %s', files_in_scope)
            logger.info('Funcs in scope: %s', funcs_in_scope)
        else:
            logger.critical('[CRITICAL] No files in scope found in the POI report... aborting')
            exit(1)
        
        # Get poi reports
        poi_report = Helper.load_candidate_pois(poi_report_path)
        poi_report_meta = POIReport.model_validate(yaml.safe_load(open(poi_report_path, 'r')))

        # Run IssueGuy & get Issue Ticket
        logger.info('🕵🏻 IssueGuy Running\n')
        
        curr_issue_guy_llm_index = 0
        # =======================================================================================
        # 🧠 Reasoning loop
        #    - This is basically handling any weirdness happening 
        #      during the LLM reasoning process (e.g., no budget left, context exceeded, etc.)
        while True:
            issueGuy = IssueGuy(project_name=project_name, poi_report=poi_report)
            
            issue_guy_llm = Config.issue_llms[curr_issue_guy_llm_index]
            issueGuy.__LLM_MODEL__ = issue_guy_llm
            issueGuy.llm  = issueGuy.get_llm_by_name(
                                                     issue_guy_llm, 
                                                     **issueGuy.__LLM_ARGS__,
                                                     raise_on_budget_exception=issueGuy.__RAISE_ON_BUDGET_EXCEPTION__,
                                                     raise_on_rate_limit_exception=issueGuy.__RAISE_ON_RATE_LIMIT_EXCEPTION__
                                                    )
            logger.info('  -  Running IssueGuy with LLM: %s', issueGuy.__LLM_MODEL__)
            try:
                res = issueGuy.invoke()
                # NOTE: if the invoke succeeds, we can reset the nap counter
                issue_guy_how_many_naps = 0
                break
            except (LLMApiBudgetExceededError, LLMApiRateLimitError) as e:
                
                if isinstance(e, LLMApiBudgetExceededError):
                    logger.warning(f'  💸 LLM API budget exceeded for {issue_guy_llm}')
                else:
                    logger.warning(f'  ⌛️ LLM API rate limit exceeded for {issue_guy_llm}')

                curr_issue_guy_llm_index += 1

                if curr_issue_guy_llm_index >= len(Config.issue_llms):
                    logger.info(' 😶‍🌫️ No more LLMs to try. pQ go to sleep!')

                    # Reset the LLM index
                    curr_issue_guy_llm_index = 0
                    
                    if Config.nap_mode == True and issue_guy_how_many_naps < Config.nap_becomes_death_after:
                        issue_guy_how_many_naps += 1
                        logger.info('😴 Taking nap number %s...', issue_guy_how_many_naps)
                        Helper.take_a_nap()
                        # Now we are going back to the first LLM (we reset the curr_issue_guy_llm_index to 0)
                        logger.info('🫡 Nap time is over! Back to work...')
                    else:
                        total_cost = agentlib.lib.agents.agent.global_event_dumper.total_cost_per_million / 1_000_000
                        logger.info(' 💸 Total cost of the failing patching process: %s\n', total_cost)
                        exit(1)
                else:
                    # NOTE: we are gonna try IssueGuy with the next LLM...
                    # This is going back to the reasoning loop
                    continue

            except Exception as e:
                logger.critical(f'  💀 Error running IssueGuy: {e}')
                import sys; sys.exit(1)
        
        # 🧠 End of the while reasoning loop, we are out of the LLM
        # =======================================================================================

        issueTicket = res.value
        logger.info('%s', issueTicket)

        # Format Context Report
        initial_context_report = InitialContextReport(
                                                        project_name=project_name, 
                                                        project_language=project_language,
                                                        issueTicket=issueTicket,
                                                        files_in_scope=files_in_scope
                                                    )
        
        return poi_report, poi_report_meta, issueTicket, initial_context_report, funcs_in_scope

    def get_project_info(project_yaml_path: str) -> Tuple[str, str]:
        with open(project_yaml_path, 'r') as f:
            project_yaml = AugmentedProjectMetadata.model_validate(yaml.safe_load(f))

        project_name = project_yaml.get_project_name()
        project_language = project_yaml.language
        
        # lower case it
        project_language = project_language.lower()

        if project_language == "c++":
            # Map C++ to C
            project_language = "c"
        elif project_language == "jvm":
            # Map jvm to simply Java
            project_language = "java"
        return project_name, project_language

    def clean_entry(crash_entry: str) -> dict:
        new_dict = dict()
        for key, value in crash_entry.items():
            if key not in ['symbol_offset', 'symbol_size']:
                new_dict[key] = value
        return new_dict

    def load_candidate_pois(poi_report: Path) -> list[dict]:
        def load_sanitizer_name(poi_report: POIReport) -> str:
            if not poi_report.additional_information:
                return poi_report.pois[0].reason

            # NOTE: the additional_information field is a dict.
            if 'asan_report_data' in poi_report.additional_information.keys():
                asan_report_data = poi_report.additional_information['asan_report_data']
                if 'sanitizer' in asan_report_data:
                    return asan_report_data['sanitizer']
                else:
                    return ""
            else:
                return ""
        
        report = POIReport.model_validate(yaml.safe_load(open(poi_report, 'r')))
        
        cleaned_report = dict()
        # NOTE:
        # This cleaned report will be like this:
        # cleaned_report['stack_traces']['main'] = <list-of-call-locations>
        # cleaned_report['stack_traces']['free'] = <list-of-call-locations>
        # cleaned_report['stack_traces']['malloc'] = <list-of-call-locations>
        cleaned_report['stack_traces'] = {}
        
        # NOTE: For now, we want to get only the main stack trace.
        if 'main' not in report.stack_traces:
            assert False, "No 'main' stack trace in the POI report. BUG!"

        for stack_trace_id, stack_trace_info in report.stack_traces.items():

            logger.info("Processing stack trace %s with reason %s", stack_trace_id, stack_trace_info.reason)
            my_stack_trace = []
            
            # Get all the call_locations from the stack trace
            stack_trace_call_locations = stack_trace_info.call_locations

            for call_trace_entry in stack_trace_call_locations:
                # If the source location is not set, we have no idea where this file is, skip.
                if not call_trace_entry.source_location:
                    continue

                if not call_trace_entry.source_location.file_name:
                    # skip this, it is out of scope!
                    continue
                
                if call_trace_entry.source_location.focus_repo_relative_path:
                    cleaned_loc = dict()
                    cleaned_loc['function_name'] = call_trace_entry.source_location.function_name
                    cleaned_loc['function_index_key'] = call_trace_entry.source_location.function_index_key
                    cleaned_loc['line_number'] = call_trace_entry.source_location.line_number
                    cleaned_loc['line_text'] = call_trace_entry.source_location.line_text
                    cleaned_loc['source_relative_file_path'] = call_trace_entry.source_location.focus_repo_relative_path
                    my_stack_trace.append(cleaned_loc)

            cleaned_report['stack_traces'][stack_trace_id] = my_stack_trace
        
        cleaned_report['crash_reason'] = report.crash_reason
        cleaned_report['sanitizer_name'] = load_sanitizer_name(report)

        return cleaned_report

    def load_files_and_funcs_in_scope_from_poi(poi_report: Path, cp, func_resolver) -> Tuple[Set[str], Set[FUNCTION_INDEX_KEY]]:
        
        def is_file_reachable(file_name: str, cp, func_resolver) -> bool:
            for funckey in func_resolver.find_by_filename(file_name):
                funckeyindex = func_resolver.get(funckey)
                
                if funckeyindex.focus_repo_relative_path is None:
                    # Do not consider stuff outside the focus repo
                    continue
                
                relative_file_path = str(func_resolver.get(funckey).focus_repo_relative_path).lstrip("/")
                full_file_path = os.path.join(cp.project_source, relative_file_path)

                if os.path.exists(full_file_path):
                    # Ok, we can open the file! :D
                    return True

            # If we are here, it means we could not find the file in the focus repo.
            return False
        
        def find_file(project_source: Path, file_name: str) -> str:
            for root, _, files in os.walk(project_source):
                for filename in files:
                    if fnmatch.fnmatch(filename, file_name):
                        return os.path.join(root, filename)
            return ""

        def get_compiled_file(file_name: str, cp) -> str:
            file_name = str(file_name)
            suffix = file_name.split('.')[-1]
            if suffix in ['c', 'cpp', 'h', 'hpp']:
                to_find_file = file_name + '.in'
                file_path = find_file(cp.project_source, to_find_file)
                if file_path:
                    logger.info("✅ Found compiled file for %s: %s", file_name, file_path)
                    return os.path.relpath(file_path, cp.project_source)
            
            # If we are here, it means we could not find the file in the focus repo.
            return ""

        logger.info("🔃 Loading files in scope from POI report: %s", poi_report)
        pois = POIReport.model_validate(yaml.safe_load(open(poi_report, 'r')))
        
        files_in_scope = set()
        funcs_in_scope = set()
        
        stack_traces = pois.stack_traces

        # We are gonna scan all the stack_traces to grab the file in scope!
        for st_id, st_info in stack_traces.items():
            logger.info("st_info.reason %s", st_info.reason)
            for call_location in st_info.call_locations:
                # If the source location is not set, we have no idea where this file is, skip.
                if not call_location.source_location:
                    continue
                
                # Also skip this, it is out of scope!
                if not call_location.source_location.file_name:
                    continue
                elif call_location.source_location.full_file_path and "fuzzer" in str(call_location.source_location.full_file_path):
                    # Little hack to avoid to include fuzzer code as in scope.
                    continue

                if not is_file_reachable(call_location.source_location.file_name, cp, func_resolver):
                    # NOTE: file is not reachable...
                    try:
                        if Config.resolve_compile_generated_files:
                            compiled_file = get_compiled_file(call_location.source_location.file_name, cp)
                            if compiled_file:
                                # NOTE: the get_compiled_file looks into the focused repo manually.
                                #       so we know that this file is in scope.
                                files_in_scope.add(compiled_file)
                            else:
                                logger.info("   🚮 File %s is not reachable, discarding it from the POI report (unknown precompiled version)", call_location.source_location.file_name)
                                continue
                        else:
                             # 👴🏻 Old behavior, skip any heuristic...
                            logger.info("   🚮 File %s is not reachable, discarding it from the POI report.", call_location.source_location.file_name)
                            continue
                    except Exception as e:
                        # 👴🏻🙅🏻‍♂️ Old behavior in case heuristics explodes...
                        logger.warning("   🚮 File %s is not reachable, discarding it from the POI report.", call_location.source_location.file_name)
                        continue
                else:
                    if call_location.source_location.focus_repo_relative_path and str(call_location.source_location.focus_repo_relative_path) not in files_in_scope:
                        logger.info("   👀 Adding file %s to the in-scope files.", call_location.source_location.focus_repo_relative_path)
                        files_in_scope.add(str(call_location.source_location.focus_repo_relative_path))
                        if call_location.source_location.function_index_key:
                            funcs_in_scope.add(call_location.source_location.function_index_key)
        
        return files_in_scope, funcs_in_scope

    def load_crash_reason(poi_report: Path) -> str:

        report = POIReport.model_validate(yaml.safe_load(open(poi_report, 'r')))
        
        if not report.additional_information:
            sanitizer_name = report.pois[0].reason
            try:
                crash_reason = sanitizer_name.split(":")[-1]
                return crash_reason
            except:
                return sanitizer_name

        if 'asan_report_data' in report.additional_information.keys():
            asan_report_data:dict = report.additional_information['asan_report_data']
            if 'crash_type' in asan_report_data.keys():
                return asan_report_data['crash_type']
        return ""

    def load_crash_reason_hint(reason: str) -> str:
        # Check if in the prompts/root-cause-hints we 
        # have a template for the given reason.
        template_path = Path('/src/patcherq/prompts/root-cause-hints')
        if (template_path / f'{reason}.hint').exists():
            with open(template_path / f'{reason}.hint', 'r') as f:
                return f.read()
        return ""

    def load_patch_hint(reason: str) -> str:
        # Check if in the prompts/patch-hints we 
        # have a hint for the given reason.
        hint_path = Path('/src/patcherq/prompts/how-to-patch-hints')
        if (hint_path / f'{reason}.hint').exists():
            with open(hint_path / f'{reason}.hint', 'r') as f:
                return f.read()
        return ""

    def load_example_patch_report_by_language(project_language:str) -> str:
        # Load the example patch report based on the project language
        project_language = project_language.lower()
        example_patch_path = Path(f'/src/patcherq/prompts/patch-report-examples/{project_language}.patch_report')
        if example_patch_path.exists():
            with open(example_patch_path, 'r') as f:
                return f.read()
        return ""

    def load_example_patch_report_by_language(project_language:str) -> str:
        # Load the example patch report based on the project language
        project_language = project_language.lower()
        example_patch_path = Path(f'/src/patcherq/prompts/patch-report-examples/{project_language}.patch_report')
        if example_patch_path.exists():
            with open(example_patch_path, 'r') as f:
                return f.read()
        return ""
