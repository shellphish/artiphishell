
import os
import logging
import yaml
import random
import re
import time
import agentlib
import uuid
import shutil
import json
import networkx as nx
from collections import defaultdict
from functools import reduce

from agentlib import LocalObject, ObjectParser
from typing import List, Dict, Tuple
from rich import print
from datetime import datetime, timedelta
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

from shellphish_crs_utils.function_resolver import LocalFunctionResolver, RemoteFunctionResolver
from .toolbox import PeekSrcSkill
from shellphish_crs_utils.models.oss_fuzz import AugmentedProjectMetadata
from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject
from agentlib.lib.common import LLMApiBudgetExceededError, LLMApiContextWindowExceededError
from shellphish_crs_utils.models.indexer import FunctionIndex

from .agents import HongweiScan, HongweiValidate
from .utils import  HarnessResolver, AnalysisGraphAPI, reduce_cycle
from .analysis_graph_api import AnalysisGraphAPI
from .config import Config

from scanguy.config import Config

logger = logging.getLogger("scanguy")
logger.setLevel(logging.INFO)

RETRY_LIMIT = 3  # Number of retries for failed tasks (with invalid format)

class ScanGuy:

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.target_metadata = self.kwargs['target_metadata']
        self.target_functions_jsons_dir = self.kwargs['target_functions_jsons_dir']
        self.function_index = self.kwargs['function_index']
        self.project_id = self.kwargs['project_id']
        self.all_sink_to_paths = defaultdict(list)
        self.sink_index_key_to_nodes = defaultdict(list)
        self.output_dir = self.kwargs['output_dir']

        # Load data from the agumented project metadata
        with open(self.target_metadata, 'r') as f:
            self.project_yaml = AugmentedProjectMetadata.model_validate(yaml.safe_load(f))
        self.project_language = self.project_yaml.language.value
        self.project_name = self.project_yaml.get_project_name()
        assert self.project_name != None

        self.aggregated_harness_info = None
        with open(self.kwargs['aggregated_harness_info_file'], "r") as file:
            self.aggregated_harness_info = yaml.safe_load(file)

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

        ########################################################
        # 💆🏻‍♂️ MANAGERS FOR MAKE EVERYTHING A LITTLE EASIER
        ########################################################

        # A nice object to launch neo4j queries
        self.analysis_graph_api = AnalysisGraphAPI()

        ########################################################

        # ######################################################
        # 🧰 LOAD THE LLM SKILLS
        ########################################################
        self.peek_src = PeekSrcSkill(
            function_resolver=self.func_resolver,
            project_metadata=self.project_yaml,
            analysis_graph_api=self.analysis_graph_api,
            **kwargs
        )


    def get_orig_nodes(self, paths) -> list:
        sink_graphs = []
        for path in paths:
            try:
                rels = path.relationships
                if not rels:
                    continue
                G = nx.DiGraph()
                for rel in rels:
                    G.add_edge(rel.start_node['identifier'], rel.end_node['identifier'])
                sink_graphs.append(G)
            except Exception as e:
                logger.error(f"Error parsing path in get_orig_nodes: {e}")
                import traceback
                tb = traceback.format_exc()
                logger.error(f"Traceback: {tb}")
                continue

        if sink_graphs:
            try:
                G_merged = reduce(nx.compose, sink_graphs)
                new_nodes, G_without_cycle = reduce_cycle(G_merged) 
            except Exception as e:
                logger.error(f"Error in reduce_cycle or merging graphs: {e}")
                all_nodes = set()
                for G in sink_graphs:
                    all_nodes.update(G.nodes)
                new_nodes = list(all_nodes)
        else:
            logger.error("No valid paths to merge.")
            new_nodes = []

        nodes = []
        for key in new_nodes:
            code = self.func_resolver.get_code(key)[-1]
            name = self.func_resolver.get_funcname(key)
            node = {
                "key": key,
                "code": code,
                "name": name,
            }
            nodes.append(node)

        return nodes

    def parse_vuln_scan_output(self, text:str) -> dict:
        """
        Parse the model output and return a dictionary containing:
        - output: the combined <reasoning_process> and <vuln_detect> sections
        - predicted_is_vulnerable: 'yes', 'no', or 'invalid format'
        - predicted_vulnerability_type: CWE identifier or 'N/A'
        """
        # Extract the <reasoning_process> section
        think_match = re.search(r'(<reasoning_process>[\s\S]*?</reasoning_process>)', text)
        # Extract the <vuln_detect> section
        vuln_match = re.search(r'(<vuln_detect>[\s\S]*?</vuln_detect>)', text)

        if think_match and vuln_match:
            combined_output = think_match.group(1) + "\n" + vuln_match.group(1)

            # Extract the vulnerability judgment and type
            judge_match = re.search(r'#judge:\s*(yes|no)', vuln_match.group(1), re.IGNORECASE)
            type_match  = re.search(r'#type:\s*([A-Za-z0-9\-]+)', vuln_match.group(1), re.IGNORECASE)

            predicted_is_vulnerable = judge_match.group(1).lower() if judge_match else "invalid format"
            predicted_vulnerability_type = type_match.group(1).upper() if type_match else "N/A"

            # If not vulnerable, enforce type as N/A
            if predicted_is_vulnerable == "no":
                predicted_vulnerability_type = "N/A"

            return {
                "output": combined_output,
                "predicted_is_vulnerable": predicted_is_vulnerable,
                "predicted_vulnerability_type": predicted_vulnerability_type
            }
        return {
            "output": text,
            "predicted_is_vulnerable": "invalid format",
            "predicted_vulnerability_type": "N/A"
        }
    
    def run_scan(self, hongweiScan:HongweiScan):
        scan_res ={
            "output": "Dummy",
            "predicted_is_vulnerable": "invalid format",
            "predicted_vulnerability_type": "N/A"
        }
        for _ in range(RETRY_LIMIT):
            try:
                result = hongweiScan.invoke()
                parsed_res = result.value
                if result.value.get('output', "") == "Agent stopped due to max iterations.":
                    conversation=hongweiScan.chat_history
                    model = hongweiScan.get_current_llm()
                    try:
                        logger.warning("⚠️ Agent stopped due to max iterations, trying to recover...")
                        res=model.invoke(conversation).content
                        parsed_res = self.parse_vuln_scan_output(res)
                    except Exception as e:
                        logger.error(f"❌ Error invoking model when trying to recover agent stopped due to max iterations: {e}")
                scan_res = parsed_res
            except LLMApiContextWindowExceededError:
                try: 
                    logger.warning("⚠️ Context window exceeded, trying to recover...")
                    conversation=hongweiScan.chat_history
                    model = hongweiScan.get_current_llm()
                    # If the context window is exceeded, we try to trim the messages

                    trimmed_history = conversation[:-1]
                    while trimmed_history and trimmed_history[-1].additional_kwargs.get("tool_calls"):
                        trimmed_history = trimmed_history[:-1]
                    if not trimmed_history:
                        logger.error("❌ No messages left after trimming, cannot invoke model.")
                        scan_res = {
                            "output": "INPUT EXCEEDS CONTEXT WINDOW",
                            "predicted_is_vulnerable": "invalid format",
                            "predicted_vulnerability_type": "N/A"
                        }
                    res=model.invoke(trimmed_history).content
                    parsed_res = self.parse_vuln_scan_output(res)
                    scan_res = parsed_res
                except Exception as e:
                    logger.error(f"❌ Error invoking model after context window exceeded: {e}")
                    scan_res = {
                        "output": "INPUT EXCEEDS CONTEXT WINDOW",
                        "predicted_is_vulnerable": "invalid format",
                        "predicted_vulnerability_type": "N/A"
                    }
            except Exception as e:
                import traceback
                tb = traceback.format_exc()
                logger.error(f"❌ Unknown error in scan.invoke(): {tb}")
                scan_res = {
                    "output": tb,
                    "predicted_is_vulnerable": "invalid format",
                    "predicted_vulnerability_type": "N/A"
                }
            if scan_res.get("predicted_is_vulnerable") != "invalid format":
                # If we got a valid format, we break the retry loop
                break
            else:
                logger.warning(f"❗️ Invalid format detected in scan result, retrying... ({_+1}/{RETRY_LIMIT})")
                hongweiScan.CWE_PROMPT+=  "YOU do not need to list and analyze each CWE, and you do not need to analyze how to exploit the vulnerability. Just tell me if the function is vulnerable or not, and if it is, what is the CWE type of the vulnerability. Do not even mention CWE numbers that the target function is not vulnerable to. Please ensure the output format is correct and includes the <reasoning_process> and <vuln_detect> sections."
        return scan_res

    def run_validate(self, hongweiValidate:HongweiValidate):
        validate_res = {
            "output": "Dummy",
            "predicted_is_vulnerable": "invalid format",
            "predicted_vulnerability_type": "N/A"
        }
        for _ in range(RETRY_LIMIT):
            try:
                result = hongweiValidate.invoke()
                parsed_res = result.value
                if result.value.get('output', "") == "Agent stopped due to max iterations.":
                    conversation=hongweiValidate.chat_history
                    model = hongweiValidate.get_current_llm()
                    try:
                        logger.warning("⚠️ Agent stopped due to max iterations, trying to recover...")
                        res=model.invoke(conversation).content
                        parsed_res = self.parse_vuln_scan_output(res)
                    except Exception as e:
                        logger.error(f"❌ Error invoking model when trying to recover agent stopped due to max iterations: {e}")
                validate_res = parsed_res
            except LLMApiContextWindowExceededError:
                try: 
                    logger.warning("⚠️ Context window exceeded, trying to recover...")
                    conversation=hongweiValidate.chat_history
                    model = hongweiValidate.get_current_llm()
                    # If the context window is exceeded, we try to trim the messages

                    trimmed_history = conversation[:-1]
                    while trimmed_history and trimmed_history[-1].additional_kwargs.get("tool_calls"):
                        trimmed_history = trimmed_history[:-1]
                    if not trimmed_history:
                        logger.error("❌ No messages left after trimming, cannot invoke model.")
                        validate_res = {
                            "output": "INPUT EXCEEDS CONTEXT WINDOW",
                            "predicted_is_vulnerable": "invalid format",
                            "predicted_vulnerability_type": "N/A"
                        }
                    res=model.invoke(trimmed_history).content
                    parsed_res = self.parse_vuln_scan_output(res)
                    validate_res = parsed_res
                except Exception as e:
                    logger.error(f"❌ Error invoking model after context window exceeded: {e}")
                    # If we cannot recover, we return a default value
                    validate_res = {
                        "output": "INPUT EXCEEDS CONTEXT WINDOW",
                        "predicted_is_vulnerable": "invalid format",
                        "predicted_vulnerability_type": "N/A"
                    }
            except Exception as e:
                import traceback
                tb = traceback.format_exc()
                logger.error(f"❌ Unknown error in scan.invoke(): {tb}")
                validate_res = {
                    "output": tb,
                    "predicted_is_vulnerable": "invalid format",
                    "predicted_vulnerability_type": "N/A"
                }
            if validate_res.get("predicted_is_vulnerable") != "invalid format":
                # If we got a valid format, we break the retry loop
                break
            else:
                logger.warning(f"❗️ Invalid format detected in validate result, retrying... ({_+1}/{RETRY_LIMIT})")
                hongweiValidate.CWE_PROMPT += "YOU do not need to list and analyze each CWE, and you do not need to analyze how to exploit the vulnerability. Just tell me if the function is vulnerable or not, and if it is, what is the CWE type of the vulnerability. Do not even mention CWE numbers that the target function is not vulnerable to. Please ensure the output format is correct and includes the <reasoning_process> and <vuln_detect> sections."
        return validate_res
            
    def _scan_worker(self, sink_index_key):
        logger.info(f"Processing POI: {sink_index_key}")
        sink_full_info:FunctionIndex = self.func_resolver.get(sink_index_key)
        sink_funcname:str = self.func_resolver.get_funcname(sink_index_key)

        if sink_full_info is None:
            # NOTE: something terribly broken?
            logger.info(f" 🚮 POI {sink_full_info} not found in the function index, skipping...")
            return None

        orig_nodes = self.sink_index_key_to_nodes.get(sink_index_key, [])

        hongweiScan = HongweiScan(
            CODE=self.func_resolver.get_code(sink_index_key)[-1],
            NODES= orig_nodes,
            CWE_PROMPT=self.get_cwe_prompt(self.project_language),
        )

        result = self.run_scan(hongweiScan)
        result["function"] = sink_funcname
        result["file"]     = str(sink_full_info.target_container_path)
        result["function_index_key"] = sink_index_key

        return result

    
    def _validate_worker(self, sink_index_key, reasoning_process):
        logger.info(f"Processing POI: {sink_index_key}")
        sink_full_info:FunctionIndex = self.func_resolver.get(sink_index_key)
        sink_funcname:str = self.func_resolver.get_funcname(sink_index_key)

        if sink_full_info is None:
            # NOTE: something terribly broken?
            logger.info(f" 🚮 POI {sink_full_info} not found in the function index, skipping...")
            return None

        orig_nodes = self.sink_index_key_to_nodes.get(sink_index_key, [])
        retry_num = 5
        code = ""
        while retry_num > 0:
            try:
                code = self.func_resolver.get_code(sink_index_key)[-1]
            except Exception as e:
                logger.error(f"Error getting code for sink {sink_index_key}: {e}")
                code = ""
            
            retry_num -= 1
            if not code:
                logger.warning(f"No code found for {sink_index_key}, retrying... ({retry_num})")
                time.sleep(3)
            else:
                break

        hongweiValidate = HongweiValidate(
            CODE=code,
            NODES= orig_nodes,
            REASONING= reasoning_process,
            CWE_PROMPT=self.get_cwe_prompt(self.project_language)
        )

        result = self.run_validate(hongweiValidate)
        result["function"] = sink_funcname
        result["file"]     = str(sink_full_info.target_container_path)
        result["function_index_key"] = sink_index_key

        return result
    
    def get_harness_prefix_in_scope(self):
        if self.project_language == "c" or self.project_language == "c++":
            harness_prefix = "LLVM"
        else:
            harness_prefix = "fuzzerTest"

        return harness_prefix

    def _fetch_sources(self):
        """
        Fetch source nodes from function resolver.
        """
        retry_num = 5
        sources = []
        while retry_num > 0:
            try:
                if self.project_language == "c" or self.project_language == "c++":
                    # For C/C++ projects, we look for LLVM harnesses
                    sources = list(self.func_resolver.find_by_funcname("LLVMFuzzerTestOneInput"))
                else:
                    sources = list(self.func_resolver.find_by_funcname("fuzzerTestOneInput"))
                    sources.extend(list(self.func_resolver.find_functions_with_annotation("@FuzzTest")))
            except Exception as e:
                logger.error(f"Error fetching sources: {e}")
                sources = []
            
            retry_num -= 1
            if sources:
                logger.info(f"Found {len(sources)} sources.")
                break
            else:
                logger.warning(f"No sources found, retrying... ({retry_num})")
                time.sleep(30)
        
        return sources
    
    def get_cwe_prompt(self, language: str) -> str:
        if self.project_language == "c" or self.project_language == "c++":
            CWE_PROMPT = """
            - CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer. Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced. This can cause read or write operations to be performed on memory locations that may be associated with other variables, data structures, or internal program data.
            - CWE-416: Use After Free. The product reuses or references memory after it has been freed. At some point afterward, the memory may be allocated again and saved in another pointer, while the original pointer references a location somewhere within the new allocation. Any operations using the original pointer are no longer valid because the memory belongs to the code that operates on the new pointer.
            - CWE-476: NULL Pointer Dereference. The product dereferences a pointer that it expects to be valid but is NULL.
            """
        else:
            CWE_PROMPT = """
            - CWE-74: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection'). The product constructs all or part of a command, data structure, or record using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify how it is parsed or interpreted when it is sent to a downstream component.
            - CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal'). The product uses external input to construct a pathname that is intended to identify a file or directory that is located underneath a restricted parent directory, but the product does not properly neutralize special elements within the pathname that can cause the pathname to resolve to a location that is outside of the restricted directory.
            - CWE-918: Server-Side Request Forgery (SSRF). The web server receives a URL or similar request from an upstream component and retrieves the contents of this URL, but it does not sufficiently ensure that the request is being sent to the expected destination.
            - CWE-502: Deserialization of Untrusted Data. The product deserializes untrusted data without sufficiently ensuring that the resulting data will be valid.
            - CWE-917: Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection'). The product constructs all or part of an expression language (EL) statement in a framework such as a Java Server Page (JSP) using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended EL statement before it is executed.
            - CWE-90: Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection'). The product constructs all or part of an LDAP query using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended LDAP query when it is sent to a downstream component.
            - CWE-154: Improper Neutralization of Variable Name Delimiters. The product receives input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could be interpreted as variable name delimiters when they are sent to a downstream component.
            - CWE-470: Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection'). The product uses external input with reflection to select which classes or code to use, but it does not sufficiently prevent the input from selecting improper classes or code.
            - CWE-777: Regular Expression without Anchors. The product uses a regular expression to perform neutralization, but the regular expression is not anchored and may allow malicious or malformed data to slip through.
            - CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
            - CWE-643: Improper Neutralization of Data within XPath Expressions ('XPath Injection'). The product uses external input to dynamically construct an XPath expression used to retrieve data from an XML database, but it does not neutralize or incorrectly neutralizes that input. This allows an attacker to control the structure of the query.
            - CWE-611: Improper Restriction of XML External Entity Reference. The product processes an XML document that can contain XML entities with URIs that resolve to documents outside of the intended sphere of control, causing the product to embed incorrect documents into its output.
            - CWE-835: Loop with Unreachable Exit Condition ('Infinite Loop')
            """
        return CWE_PROMPT


    def start(self):

        #####################################################
        # 🚰 First we are getting the sinks based on the mode
        #####################################################
            # These are the ranked functions as per code-swipe

        entry_points = self._fetch_sources()
        if not entry_points:
            logger.error("No entry points found, cannot proceed with scan.")
            return
        
        all_sinks = []
        sinks_and_more_paths = []
        retry_query_num = 5
        while retry_query_num > 0:
            try:
                sinks_and_more_paths = self.analysis_graph_api.get_more_paths(entry_points)
                all_sinks = [sink[0] for sink in sinks_and_more_paths]
            except Exception as e:
                logger.error(f"Error fetching sinks and paths: {e}")
            
            retry_query_num -= 1

            if all_sinks:
                logger.info(f"Found {len(all_sinks)} sinks.")
                break
            else:
                logger.warning(f"No sinks found, retrying... ({retry_query_num})")
                time.sleep(30)

        dedup_code_set = set()
        dedup_sinks = []
        for sink_index_key in all_sinks:
            code = ""
            try:
                code = self.func_resolver.get_code(sink_index_key)[-1]
            except Exception as e:
                logger.error(f"Error getting code for {sink_index_key}: {e}")
                continue
            if code not in dedup_code_set:
                dedup_code_set.add(code)
                dedup_sinks.append(sink_index_key)
        all_sinks = dedup_sinks
        # filter so that we only keep the sinks that are in the focus repo
        focus_repo_keys = []
        try:
            focus_repo_keys = self.func_resolver.get_focus_repo_keys(focus_repo_container_path="")
        except Exception as e:
            logger.error(f"Error getting focus repo keys: {e}")
        if focus_repo_keys:
            all_sinks = [sink for sink in all_sinks if sink in focus_repo_keys]

        for sink_index_key, path in sinks_and_more_paths:
            if sink_index_key in all_sinks:
                self.all_sink_to_paths[sink_index_key].append(path)

        for sink_index_key in self.all_sink_to_paths:
            nodes = self.get_orig_nodes(self.all_sink_to_paths[sink_index_key])
            self.sink_index_key_to_nodes[sink_index_key] = nodes

        max_workers = 100
        workers = max_workers or len(all_sinks)

        all_results = []
        # do this to prevent race conditions
        sink_key = all_sinks[0]

        orig_nodes = self.sink_index_key_to_nodes.get(sink_key, [])
        retry_num = 5
        code = ""
        while retry_num > 0:
            try:
                code = self.func_resolver.get_code(sink_key)[-1]
            except Exception as e:
                logger.error(f"Error getting code for sink {sink_key}: {e}")
            
            retry_num -= 1
            if not code:
                logger.warning(f"No code found for {sink_key}, retrying... ({retry_num})")
                time.sleep(3)
            else:
                break
        
        hongweiScan = HongweiScan(
            CODE= code,
            NODES= orig_nodes,
            CWE_PROMPT= self.get_cwe_prompt(self.project_language),
        )
        time.sleep(3)

        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

        #scan
        count = 0
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(self._scan_worker, sink): sink for sink in all_sinks}
            for future in as_completed(futures):
                try:
                    if future.result() is not None:
                        all_results.append(future.result())
                    else:
                        logger.warning(f"Scan result for {futures[future]} is None, skipping...")
                        all_results.append({
                            "function": futures[future],
                            "output": "Scan result is None",
                            "predicted_is_vulnerable": "invalid format",
                            "predicted_vulnerability_type": "N/A"
                        })
                except Exception as e:
                    all_results.append({
                        "function": futures[future],
                        "output": f"Error scanning {futures[future]}: {e}",
                        "predicted_is_vulnerable": "invalid format",
                        "predicted_vulnerability_type": "N/A"
                    })
                    logger.error(f"Error scanning {futures[future]}: {e}", exc_info=True)
                
                count += 1
                if count % 100 == 0:
                    with open(os.path.join(self.output_dir,"scan_results.json"), "w", encoding="utf-8") as f:
                        json.dump(all_results, f, indent=2, ensure_ascii=False)
                    logger.info(f"Flushed {count} scan results to scan_results.json")

        with open(os.path.join(self.output_dir,"scan_results.json"), "w", encoding="utf-8") as f:
            json.dump(all_results, f, indent=2, ensure_ascii=False)

        # validate
        
        with open(os.path.join(self.output_dir,"scan_results.json"), "r", encoding="utf-8") as f:
            scan_results = json.load(f)

        sinks_to_validate: list[tuple[str, str]] = []
        for entry in scan_results:
            if entry.get("predicted_is_vulnerable") == "yes":
                func_key = entry["function_index_key"]
                m = re.search(
                    r'(<reasoning_process>[\s\S]*?</reasoning_process>)',
                    entry.get("output", "")
                )
                reasoning = m.group(1) if m else ""
                sinks_to_validate.append((func_key, reasoning))

        validate_results: list[dict] = []
        count = 0
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(self._validate_worker, func_key, reasoning): func_key
                for func_key, reasoning in sinks_to_validate
            }
            for future in as_completed(futures):
                try:
                    if future.result() is not None:
                        validate_results.append(future.result())
                    else:
                        logger.warning(f"Validate result for {futures[future]} is None, skipping...")
                        validate_results.append({
                            "function": futures[future],
                            "output": "Validate result is None",
                            "predicted_is_vulnerable": "invalid format",
                            "predicted_vulnerability_type": "N/A"
                        })
                except Exception as e:
                    validate_results.append({
                        "function": futures[future],
                        "output": f"Error validating {futures[future]}: {e}",
                        "predicted_is_vulnerable": "invalid format",
                        "predicted_vulnerability_type": "N/A"
                    })
                    logger.error(f"Error scanning {futures[future]}: {e}", exc_info=True)
                
                count += 1
                if count % 100 == 0:
                    with open(os.path.join(self.output_dir,"validate_results.json"), "w", encoding="utf-8") as f:
                        json.dump(validate_results, f, indent=2, ensure_ascii=False)
                    logger.info(f"Flushed {count} scan results to validate_results.json")

        with open(os.path.join(self.output_dir,"validate_results.json"), "w", encoding="utf-8") as f:
            json.dump(validate_results, f, indent=2, ensure_ascii=False)

def main(**kwargs):
    scanguy = ScanGuy(**kwargs)
    scanguy.start()