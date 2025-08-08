import base64
import json
import logging
import os

import json as jsonmod
from enum import Enum
from pathlib import Path, PosixPath
from typing import List, Tuple
import httpx
from shellphish_crs_utils.function_resolver import FunctionResolver
from shellphish_crs_utils.models.crash_reports import DedupSanitizerReport
from shellphish_crs_utils.models.crs_reports import POIReport
from shellphish_crs_utils.models.indexer import FUNCTION_INDEX_KEY
from shellphish_crs_utils.models.target import HARNESS_NAME, PROJECT_NAME

PERMANENCE_SERVER_URL = os.environ.get("PERMANENCE_SERVER_URL", "http://beatty.unfiltered.seclab.cs.ucsb.edu:31337").rstrip('/')
PERMANENCE_SERVER_GLOBAL_URL = os.environ.get("PERMANENCE_SERVER_GLOBAL_URL", "http://beatty.unfiltered.seclab.cs.ucsb.edu:31337").rstrip('/')
PERMANENCE_API_SECRET = os.environ.get("PERMANENCE_API_SECRET", "!!artiphishell!!")

log = logging.getLogger(__name__)

class PermanenceClient:
    def __init__(self, function_resolver: FunctionResolver, api_key: str=PERMANENCE_API_SECRET, base_urls: List[str] = None):
        self.function_resolver = function_resolver
        self.api_key = api_key
        base_urls = base_urls or []
        if not base_urls:
            if PERMANENCE_SERVER_URL:
                base_urls.append(PERMANENCE_SERVER_URL)
            if PERMANENCE_SERVER_GLOBAL_URL and PERMANENCE_SERVER_GLOBAL_URL != PERMANENCE_SERVER_URL:
                base_urls.append(PERMANENCE_SERVER_GLOBAL_URL)

        self.base_urls = list(set(base_urls))
        self.clients = []
        for base_url in self.base_urls:
            client = httpx.Client(base_url=base_url, timeout=30)
            client.headers.update({"Shellphish-Secret": api_key})
            client.headers.update({"Content-Type": "application/json"})
            client.headers.update({"Accept": "application/json"})
            self.clients.append(client)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        for client in self.clients:
            client.close()


    def post(self, endpoint: str, json: dict):
        def encody(o):
            if hasattr(o, 'model_dump'):
                return o.model_dump()
            elif isinstance(o, PosixPath):
                return str(o)
            elif isinstance(o, bytes):
                return base64.b64encode(o).decode("utf-8")
            elif isinstance(o, Enum):
                return o.value
            return o
        try:
            json = jsonmod.loads(jsonmod.dumps(json, default=encody))
            responses = []
            errors = []
            for client in self.clients:
                try:
                    response = client.post(endpoint, json=json)
                    if response.status_code == 200:
                        responses.append({
                            'server': client.base_url,
                            'success': True,
                            'response': response.json()
                        })
                    else:
                        errors.append({
                            'server': client.base_url,
                            'success': False,
                            'response_status_code': response.status_code,
                            'response': response.text,
                            'error': f"Error {response.status_code}: {response.text}"
                        })
                except Exception as e:
                    print(f"[PERMANENCE] Post request failed for {client.base_url}: {e}")
                    log.error(f"[PERMANENCE] Post request failed for {client.base_url}: {e}", exc_info=True)
                    errors.append({
                        'server': client.base_url,
                        'success': False,
                        'error': str(e)
                    })
            if not responses:
                raise Exception("All post requests failed")
            return {
                'responses': responses,
                'errors': errors,
                'success': not bool(errors)
            }
        except Exception as e:
            print(f"[PERMANENCE] Post request failed: {e}")
            log.error(f"[PERMANENCE] Post request failed: {e}", exc_info=True)
            return None

    def upload_indexed_functions(self, project_name: PROJECT_NAME, functions: List[FUNCTION_INDEX_KEY], **kwargs):
        print("[PERMANENCE] Uploaded indexed functions: ", self.post(
            f"/indexed_functions/{project_name}",
            json={
                "functions": {func: self.function_resolver.get(func).model_dump() for func in functions},
                "extra": kwargs
            }
        ))
    def grammar_reached(self, project_name: PROJECT_NAME, harness_name: HARNESS_NAME, grammar_type: str, grammar: str, hit_files: List[Path], hit_functions: List[FUNCTION_INDEX_KEY], **kwargs):
        self.upload_indexed_functions(project_name, hit_functions)
        if 'task_name' not in kwargs and os.environ.get('TASK_NAME', None) is not None:
            kwargs['task_name'] = os.environ['TASK_NAME']
        if 'job_id' not in kwargs and os.environ.get('JOB_ID', None) is not None:
            kwargs['job_id'] = os.environ['JOB_ID']
        if 'replica_id' not in kwargs and os.environ.get('REPLICA_ID', None) is not None:
            kwargs['replica_id'] = os.environ['REPLICA_ID']
        print("[PERMANENCE] Uploaded reaching grammars attempt: ", self.post(
            f"/grammar_reached/{project_name}/{harness_name}",
            json={
                "grammar_type": grammar_type,
                "grammar": grammar,
                "hit_functions": hit_functions,
                "hit_files": [str(f) for f in hit_files],
                "extra": kwargs
            }
        ))

    def seeds_reached(self, project_name: PROJECT_NAME, harness_name: HARNESS_NAME, seeds: List[bytes], hit_files: List[Path], hit_functions: List[FUNCTION_INDEX_KEY], **kwargs):
        self.upload_indexed_functions(project_name, hit_functions)
        if 'task_name' not in kwargs and os.environ.get('TASK_NAME', None) is not None:
            kwargs['task_name'] = os.environ['TASK_NAME']
        if 'job_id' not in kwargs and os.environ.get('JOB_ID', None) is not None:
            kwargs['job_id'] = os.environ['JOB_ID']
        if 'replica_id' not in kwargs and os.environ.get('REPLICA_ID', None) is not None:
            kwargs['replica_id'] = os.environ['REPLICA_ID']
        print("[PERMANENCE] Uploaded seeds reaching functions: ", self.post(
            f"/seeds_reached/{project_name}/{harness_name}",
            json={
                "seeds": [base64.b64encode(seed).decode("utf-8") for seed in seeds],
                "hit_functions": hit_functions,
                "hit_files": [str(f) for f in hit_files],
                "extra": kwargs
            }
        ))

    def seed_reached(self, project_name: PROJECT_NAME, harness_name: HARNESS_NAME, seed: bytes, hit_functions: List[FUNCTION_INDEX_KEY], **kwargs):
        return self.seeds_reached_functions(project_name, harness_name, [seed], hit_functions, **kwargs)

    def deduplicated_pov_report(self, project_name: PROJECT_NAME, harness_name: HARNESS_NAME, pov_report: DedupSanitizerReport, crashing_seed: bytes, **kwargs):
        print("[PERMANENCE] Uploaded deduplicated pov_report: ", self.post(
            f"/deduplicated_pov_report/{project_name}/{harness_name}",
            json={
                "dedup_sanitizer_report": pov_report.model_dump(),
                "crashing_seed": base64.b64encode(crashing_seed).decode("utf-8"),
                "extra": kwargs
            }
        ))

    def poi_report(self, project_name: PROJECT_NAME, harness_name: HARNESS_NAME, poi_report: POIReport, **kwargs):
        self.upload_indexed_functions(project_name, [poi.source_location.function_index_key for poi in poi_report.pois if poi.source_location.function_index_key is not None])
        print("[PERMANENCE] Uploaded POI report: ", self.post(
            f"/poi_report/{project_name}/{harness_name}",
            json={
                "poi_report": poi_report.model_dump(),
                "extra": kwargs
            }
        ))

    def successful_patch(self, project_name: PROJECT_NAME, harness_name: HARNESS_NAME, poi_report: POIReport, patch: str, functions_attempted_to_patch: List[FUNCTION_INDEX_KEY], **kwargs):
        self.upload_indexed_functions(project_name, functions_attempted_to_patch)
        print("[PERMANENCE] Uploaded successful patch attempt: ", self.post(
            f"/successful_patch/{project_name}/{harness_name}",
            json={
                "poi_report": poi_report.model_dump(),
                "patch": patch,
                "functions_attempted_to_patch": functions_attempted_to_patch
            }
        ))

    def unsuccessful_patch_attempt(self, project_name: PROJECT_NAME, harness_name: HARNESS_NAME, poi_report: POIReport, functions_attempted_to_patch: List[FUNCTION_INDEX_KEY], reasoning: str):
        self.upload_indexed_functions(project_name, functions_attempted_to_patch)
        print("[PERMANENCE] Uploaded unsuccessful patch attempt: ", self.post(
            f"/unsuccessful_patch_attempt/{project_name}/{harness_name}",
            json={
                "poi_report": poi_report.model_dump(),
                "reasoning": reasoning,
                "functions_attempted_to_patch": functions_attempted_to_patch
            }
        ))