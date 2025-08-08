import os
import subprocess
from contextlib import contextmanager
from pathlib import Path
from typing import Optional, Tuple, List, Dict
from collections import deque
from git import Repo
import json
import logging
import random
import string
from jinja2 import Template
import yaml
from collections import defaultdict
import time
import functools

from libcodeql.client import CodeQLClient
from shellphish_crs_utils.utils import artiphishell_should_fail_on_error
from shellphish_crs_utils.function_resolver import FunctionResolver
from shellphish_crs_utils.models.oss_fuzz import AugmentedProjectMetadata
from shellphish_crs_utils.models.indexer import FunctionIndex
from analysis_graph.models.harness_inputs import HarnessInputNode
from analysis_graph.models.sarif import SARIFreport
from shellphish_crs_utils.models.aixcc_api import SARIFMetadata, Assessment
from analysis_graph.api import add_sarif_report
TESTDIR = Path(__file__).parent.parent / "tests" 
JAZZER_SANITIZER = TESTDIR / "resources" / "jazzer_sanitizer.json"
JAZZER_SINK_METHODS = TESTDIR / "resources" / "jazzer_sink_methods.yaml"
QUERY_TEMPLATES_PATH = TESTDIR/ "resources" / "codeql_queries_templates"
QUERY_PATH =  TESTDIR / "resources" / "codeql_queries"
from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject
from QuickSeed.data import CallGraphNode
from neomodel import db


_l = logging.getLogger(__name__)
# This is mainly for setting the necessary filepath required by LLM tools to avoid global variables
@contextmanager
def set_env_vars_for_llm_tools(env_vars: dict):
    # Store original values
    original_vars = {}
    for key in env_vars:
        if key in os.environ:
            original_vars[key] = os.environ[key]

    # Set new values
    os.environ.update(env_vars)

    try:
        yield
    finally:
        # Restore original values
        for key in env_vars:
            if key in original_vars:
                os.environ[key] = original_vars[key]
            else:
                del os.environ[key]


def absolute_path_finder(src_root: Path, relative_file_path: Path) -> Path:
    if os.path.exists(src_root / relative_file_path):
        return src_root / relative_file_path
    poi_src_name = os.path.basename(relative_file_path)
    for dirpath, dirnames, filenames in os.walk(src_root):
        if poi_src_name in filenames:
            poi_src_name_match = os.path.join(dirpath, poi_src_name)
            if type(relative_file_path) != str:
                relative_file_path = str(relative_file_path)
            if poi_src_name_match[-len(relative_file_path):] == relative_file_path:
                return Path(poi_src_name_match)
    return None


class WorkDirContext:
    def __init__(self, path: Path):
        self.path = path
        self.origin = Path(os.getcwd()).absolute()

    def __enter__(self):
        os.chdir(self.path)

    def __exit__(self, exc_type, exc_val, exc_tb):
        os.chdir(self.origin)


def setup_aicc_target(target_url: str, resources_dir, target_dir, target_repo_name: Optional[str] = None,
                      target_name: Optional[str] = None):
    # first verify the test dir is setup locally
    if not target_dir.exists():
        target_dir.mkdir(parents=True)

        # verify that we have an unpacked functions json output dir
    json_output_dirs = resources_dir / "json_output_dirs"
    if not json_output_dirs.exists():
        json_output_dirs.mkdir()
        json_tar = json_output_dirs.with_suffix(".tar")
        if not json_tar.exists():
            raise FileNotFoundError(f"Did not find {json_tar}")

        subprocess.run(
            ["tar", "xC", str(json_output_dirs), "-f", str(json_output_dirs.with_suffix(".tar"))],
            check=True
        )

    if target_repo_name is None:
        target_repo_name = target_url.split("/")[-1].split(".git")[0]

    # git clone if we don't already have it
    target_repo_dir = target_dir / target_repo_name
    if not target_repo_dir.exists():
        Repo.clone_from(target_url, str(target_repo_dir))

    # reset the repo and pull to update it
    repo = Repo(str(target_repo_dir))
    repo.git.reset("--hard")
    repo.git.pull()

    original_directory = os.getcwd()
    os.chdir(target_repo_dir)
    subprocess.run(["make", "cpsrc-prepare"], check=True)
    # subprocess.run(["make", "docker-pull"], check=True)
    os.chdir(original_directory)

    return target_repo_dir


def setup_oss_fuzz_debug_build(oss_debug_target: Path, project_id: str, augmented_metadata: AugmentedProjectMetadata, local_run: bool) -> OSSFuzzProject:
    """
    Setup the OSS Fuzz project and build the target
    :param target_root: Path
    :param source_root: Path
    :param local_run: bool
    :param sanitizer: str
    :return: OSSFuzzProject
    """
    debug_target_project = OSSFuzzProject(
        oss_fuzz_project_path=oss_debug_target,
        project_id=project_id,
        augmented_metadata=augmented_metadata,
        use_task_service=not local_run,
    )
    return debug_target_project

# This is a weird function why would I use this?
def find_absolute_path(path1: Path, path2: Path) -> Path:
    # Convert to Path objects
    p1 = Path(path1).resolve() if Path(path1).is_absolute() else Path(path1)
    p2 = Path(path2).resolve() if Path(path2).is_absolute() else Path(path2)
    
    # Get path parts
    parts1 = list(p1.parts)
    parts2 = list(p2.parts)
    
    # Find the longest overlapping sequence
    max_overlap_length = 0
    overlap_start = (-1, -1)
    
    for i in range(len(parts1)):
        for j in range(len(parts2)):
            current_overlap = 0
            while (i + current_overlap < len(parts1) and 
                   j + current_overlap < len(parts2) and 
                   parts1[i + current_overlap] == parts2[j + current_overlap]):
                current_overlap += 1
                
            if current_overlap > max_overlap_length:
                max_overlap_length = current_overlap
                overlap_start = (i, j)
    
    # If no overlap found
    if max_overlap_length == 0:
        # Default: join the paths
        if p2.is_absolute():
            return p2
        else:
            return p1 / p2
    
    # Construct the path using the overlap
    i, j = overlap_start
    
    # Take everything from path1 up to the overlap
    result_parts = parts1[:i + max_overlap_length]
    
    # Add remaining parts from path2 after the overlap
    result_parts.extend(parts2[j + max_overlap_length:])
    
    # Construct the resulting path
    result = Path(*result_parts)
    
    return result

def find_absolute_path2(path1: Path, path2: Path) -> Path:
    # Convert to Path objects
    p1 = Path(path1).resolve() if Path(path1).is_absolute() else Path(path1)
    p2 = Path(path2).resolve() if Path(path2).is_absolute() else Path(path2)
    
    # Get path parts
    parts1 = list(p1.parts)
    parts2 = list(p2.parts)
    p = None
    for i in range(len(parts2)-1):
        if parts2[i] == parts1[-1] and p1.joinpath(*parts2[i+1:]).exists():
            p = p1.joinpath(*parts2[i+1:])
            break
    if p:
        return p
    for i in range(1, len(parts2)):
        p = p1.joinpath(*parts2[-i:])
        if p.exists():
            return p
    if p2.is_absolute():
        return p2
    else:
        return p1 / p2

def resolve_filepath(parent_path: Path, child_path: Path)-> Optional[Path]:
    """
    Iteratively find the absolute filepath of child_path that is under the parent_path
    """
    child_path = Path(child_path)
    parent_path = Path(parent_path)
    if child_path.exists():
        return child_path
    child_path_parts = child_path.parts
    if child_path.is_absolute():
        child_path_parts = child_path_parts[1:]
    files = [file.name for file in parent_path.iterdir()]
    for i, part in enumerate(child_path_parts):
        if part in files:
            relative_path = "/".join(child_path_parts[i:])
            abs_filepath = parent_path / relative_path
            if abs_filepath.exists():
                return abs_filepath
            else:
                continue
    return None

    # FIXME: import canonical_build_artifacts or debug_build_artifacts
    # target_project.build_target( patch_path=patch_path, sanitizer = sanitizer)
    # # build the builder and runner images
    # try:
    #     # target_project.build_builder_image()
    #     # target_project.build_target(sanitizer=sanitizer)
    #     # target_project.build_runner_image()
    #     instrumentation = "libfuzzer"
    #     run_build_command(target_root, source_root, sanitizer, instrumentation)
    # except Exception as e:
    #     raise ValueError(f"Failed to build images {e}")
    # return target_project

# def setup_coverage_target(coverage_target_root: Path, source_root: Path, project_id: str):
#     """
#     Setup the OSS Fuzz project and build the target
#     :param coverage_target_root: Path
#     :param source_root: Path
#     :param local_run: bool
#     :return: None
#     """
#     OSSFuzzProject(
#         oss_fuzz_project_path=coverage_target_root
#     )

    # pass
    


def run_crash_input(target_project: OSSFuzzProject, harness_name: str, crash_input: Path, timeout: int = 300) -> Tuple[bool, str]:
    """
    Run a crash input on the target project
    :param target_project: OssFuzzProject
    :param harness_name: str
    :param crash_input: Path
    :param timeout: int
    :return: Tuple[bool, str] - (True if the crash was triggered, the crash report)
    """
    
    run_pov_res = target_project.run_pov(harness=harness_name, data_file=crash_input, timeout=timeout, sanitizer="address",
                                                  fuzzing_engine="libfuzzer" )
    
    pov = run_pov_res.pov
    if pov.triggered_sanitizers:
        pov_report_data = pov.crash_report.raw_report or pov.unparsed
        if isinstance(pov_report_data, bytes):
            pov_report_data = pov_report_data.decode("utf-8", errors="ignore")
        return True, pov_report_data
    else:
        return False, "Crash is not triggered"

def random_string(length=10):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))

# Disable this because we want to register the call relationship in the other component
# def register_call_relationship_to_analysis_graph(
#         function_resolver: FunctionResolver, 
#         source_node: Dict, 
#         target_node: Dict, 
#         call_type="direct_call", 
#         properties: Optional[Dict]={}
#         ):

#     source_filepath = source_node.get('filepath', None)
#     target_filepath = target_node.get('filepath', None)

#     source_function_name = source_node.get('function_name', None)
#     target_function_name = target_node.get('function_name', None)
#     caller_lineno = source_node.get('lineno', None)
#     if not caller_lineno:
#         caller_lineno = source_node.get('function_startline', None)
#     callee_lineno = target_node.get('lineno', None)
#     if not callee_lineno:
#         callee_lineno = target_node.get('function_startline', None)

#     if source_filepath and target_filepath and source_function_name and target_function_name and \
#     (not str(source_filepath).endswith(".class")) and (not str(target_filepath).endswith(".class")): # We skip all the functions that is in library:
#         try:
#             register_call_relationship(
#                 source_function_name,
#                 target_function_name,
#                 caller_file_name=source_filepath,
#                 callee_file_name=target_filepath,
#                 call_type = call_type,
#                 solver = function_resolver,
#                 properties=properties,
#                 caller_lineno=caller_lineno,
#                 callee_lineno=callee_lineno
#                 )
#         except Exception as e:
#             _l.error(e)
#             if artiphishell_should_fail_on_error():
#                 raise
#     else:
#         _l.warning(f"Cannot register call relationship between {source_function_name} and {target_function_name}")


def run_all_query(client: CodeQLClient, project_name: str, project_id: str, excluding_sanitizers: List=[])-> Dict: #["RegexInjection", "ReflectionCallInjection"]
    codeql_report = {}

    # Query for call graph for sanitizers
    with open(QUERY_TEMPLATES_PATH / "Sanitizer.ql.j2", "r") as f:
        sanitizer_query_template = f.read()
    query_template = Template(sanitizer_query_template)
    with open(JAZZER_SINK_METHODS, "r") as f:
        sink_methods_dict = yaml.safe_load(f)


    all_sink_methods = []
    for sanitizer_name, sink_methods in sink_methods_dict.items():
        if sanitizer_name in excluding_sanitizers:
            continue
        all_sink_methods.extend(sink_methods)
    sanitizer_name = "All"
    query = query_template.render(
        sanitizer_name=sanitizer_name, 
        sink_methods=all_sink_methods, 
        enumerate = enumerate
    )

    query_result = client.query({
        "cp_name": project_name,
        "project_id": project_id,
        "query": query
    })

        
    codeql_report[sanitizer_name] = query_result
    
    # Query for sinks
    with open(QUERY_TEMPLATES_PATH / "Sinks.ql.j2", "r") as f:
        sinks_query_template = f.read()
    query_template = Template(sinks_query_template)
    for sanitizer_name, sink_methods in sink_methods_dict.items():
        if sanitizer_name in excluding_sanitizers:
            continue
        query = query_template.render(
            sanitizer_name=sanitizer_name, 
            sink_methods=sink_methods, 
            enumerate = enumerate
        )
        query_result = client.query({
            "cp_name": project_name,
            "project_id": project_id,
            "query": query
        })
        if codeql_report.get("Sinks") is None:
            codeql_report["Sinks"] = defaultdict(list)
            codeql_report["Sinks"][sanitizer_name] = query_result
        else:
            codeql_report["Sinks"][sanitizer_name] = query_result

    # Other queries
    for ql_file in QUERY_PATH.iterdir():
        with open(ql_file, "r") as f:
            query = f.read()
        # FIXME: project id
        query_result = client.query({
            "cp_name": project_name,
            "project_id": project_id,
            "query": query
        })
        codeql_report[ql_file.stem] = query_result
    return codeql_report

def retry(max_attempts=3, delay=10, backoff=2, exceptions=(Exception,), logger=_l):
    """
    Retry decorator with exponential backoff
    
    Parameters:
    - max_attempts: Maximum number of retry attempts (default: 3)
    - delay: Initial delay between retries in seconds (default: 1)
    - backoff: Backoff multiplier (default: 2)
    - exceptions: Tuple of exceptions to catch (default: all exceptions)
    - logger: Logger to use (default: None)
    
    Usage:
    @retry(max_attempts=5, delay=2, exceptions=(ConnectionError, TimeoutError))
    def fetch_data(url):
        # Your code that might fail
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            local_max_attempts, local_delay = max_attempts, delay
            for attempt in range(1, local_max_attempts + 1):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    # If this was the last attempt, re-raise the exception
                    if attempt == local_max_attempts:
                        raise
                    
                    # Log the exception if a logger is provided
                    if logger:
                        logger.warning(
                            f"Attempt {attempt}/{local_max_attempts} for {func.__name__} failed: {e}. "
                            f"Retrying in {local_delay} seconds."
                        )
                    
                    # Sleep before next attempt with exponential backoff
                    time.sleep(local_delay)
                    local_delay *= backoff
        return wrapper
    return decorator

@retry(max_attempts=3)
def run_codeql_query(client: CodeQLClient, query: str, project_name: str, project_id: str):
    query_result = client.query({
        "cp_name": project_name,
        "project_id": project_id,
        "query": query
    })
    return query_result


def extract_diff_function_infos(commit_full_functions_dir: Path):
    diff_function_infos = []
    # Look for function/method directories
    function_list = list(commit_full_functions_dir.rglob('FUNCTION'))
    method_list = list(commit_full_functions_dir.rglob('METHOD'))
    # If no function/method info found, return all paths
    if not function_list and not method_list:
        _l.debug("No function or method info found")
        return diff_function_infos

    # Process function JSONs
    function_dir = None
    method_dir = None
    for fdir in function_list:
        if fdir.parent.name.startswith("1_"):
            function_dir = fdir
            break
    for mdir in method_list:
        if mdir.parent.name.startswith("1_"):
            method_dir = mdir
            break
    if function_dir:
        function_jsons = list(function_dir.glob('*.json'))
        for function_file in function_jsons:
            with open(function_file, 'r') as f:
                diff_function_infos.append(FunctionIndex.model_validate(json.load(f)))
    # Process method JSONs
    if method_dir:
        method_jsons = list(method_dir.glob('*.json'))
        for method_file in method_jsons:
            with open(method_file, 'r') as f:
                diff_function_infos.append(FunctionIndex.model_validate(json.load(f)))
    return diff_function_infos

def convert_function_resolver_identifier_to_call_graph_node(identifier: str, function_resolver: FunctionResolver) -> CallGraphNode:
    """
    Convert a function resolver identifier to a call graph node
    :param identifier: str
    :param function_resolver: FunctionResolver
    :return: CallGraphNode
    """
    try:
        function_info = function_resolver.get(identifier)
    except Exception as e:
        _l.error(f"Error getting function info for identifier {identifier}: {e}")
        return None
    if function_info is None:
        _l.error(f"No function info found for identifier {identifier}")
        return None
    qualified_name = function_info.full_funcname[1:] if function_info.full_funcname.startswith(".") else function_info.full_funcname
    return CallGraphNode(
        identifier=identifier,
        function_name=function_info.funcname,
        qualified_name=qualified_name,
        filepath=function_info.target_container_path,
        function_startline=function_info.start_line,
        function_endline=function_info.end_line,
        function_code=function_info.code,
    )


def parse_yajta_result(yajta_result: List):
    if not yajta_result:
        return [], []
    visited = []
    edges = []
    queue = deque(yajta_result)
    while queue:
        current_node = queue.popleft()
        current_name = current_node.get("name")
        visited.append(current_name)
        if current_node.get("children"):
            for child in current_node.get("children"):
                queue.append(child)
                child_name = child.get("name")
                if (current_name, child_name) not in edges:
                    edges.append((current_name, child_name))
    return visited, edges


def get_identifier_from_full_name(function_resolver: FunctionResolver, full_name: str) -> Optional[str]:
    """
    Get the identifier from the full name of a function
    :param function_resolver: FunctionResolver
    :param full_name: str
    :return: str or None if not found
    """
    if not full_name:
        return None
    try: 
        identifiers = list(function_resolver.resolve_with_leniency(full_name))
    except Exception as e:
        _l.error(f"Error resolving full name {full_name}: {e}")
        return None
    if len(identifiers) == 1:
        return identifiers[0]
    for identifier in identifiers:
        function_info = function_resolver.get(identifier)
        qualified_name = function_info.full_funcname[1:] if function_info.full_funcname.startswith(".") else function_info.full_funcname
        if qualified_name == full_name:
            return identifier # Return the first identifier found
    return None

def upload_crash_input_to_analysis_graph(crashing_harness_info_id, crashing_harness_info, crash_txt, is_crashing):

    with open(crash_txt, "rb") as f:
        seed_content = bytearray(f.read())

    try:
        crashing_input_id = HarnessInputNode.create_node(
                    harness_info_id=crashing_harness_info_id,
                    harness_info=crashing_harness_info,
                    content=seed_content,
                    crashing=is_crashing
                )
    except Exception as e:
        _l.warning(f"👀 Failed to create harness input node in analysis graph: {e}")
        crashing_input_id = None

    if crashing_input_id is not None:
        try:
            cid = crashing_input_id[1].identifier
            return cid
        except Exception as e:
            return None
    else:
        return None


def link_seed_to_sarif(seed_id, sarif_id, sarif_resolver):

    # NOTE: check if the sarif report exists (sarifguy should have uploaded it at this point)
    sarif_node = SARIFreport.get_node_or_none(sarif_uid=sarif_id)

    if sarif_node is None:
        # For some reasons the sarifguy did not upload the sarif report, we are gonna do it...
        covered_functions_keys = set()
        for sarif_result in sarif_resolver.get_results():
            for loc in sarif_result.locations:
                covered_functions_keys.add(loc.keyindex)
            for codeflow in sarif_result.codeflows:
                for loc in codeflow.locations:
                    covered_functions_keys.add(loc.keyindex)

        try:
            add_sarif_report(
                sarif_uid=str(sarif_id),
                sarif_type="injected",
                sarif_path=sarif_resolver.sarif_path,
                covered_functions_keys=covered_functions_keys
            )
        except Exception as e:
            _l.error(f"🙊 Failed to add sarif report {sarif_id} to analysis graph: {e}")
            return None

    # NOTE: now we connect the crashing input to the sarif report
    query = """
    MATCH (input:HarnessInputNode) WHERE input.identifier CONTAINS $seed_id
    MATCH (sarif:SARIFreport) WHERE sarif.sarif_uid = $sarif_id
    CREATE (sarif)-[:CRASHED_BY]->(input)
    RETURN input, sarif
    """
    params = {
        "seed_id": seed_id,
        "sarif_id": str(sarif_id),
    }
    results, columns = db.cypher_query(query=query, params=params, resolve_objects=True)

    return results


def check_file_size(file_path, max_size_mb=2):
    """
    Check if file size exceeds the maximum allowed size.
    
    Args:
        file_path (str): Path to the file
        max_size_mb (float): Maximum allowed size in MB

    Returns:
        bool: True if file is within size limit, False otherwise
    """

    try:
        # Get file size in bytes
        file_size = os.path.getsize(file_path)
        
        # Convert MB to bytes (1 MB = 1024 * 1024 bytes)
        max_size_bytes = max_size_mb * 1024 * 1024
        
        return file_size <= max_size_bytes
    
    except FileNotFoundError:
        _l.error(f"File not found: {file_path}")
        return False
    except OSError as e:
        _l.error(f"Error accessing file: {e}")
        return False

def emit_sarif_assesment(sarif_meta: SARIFMetadata, verdict: str="TP"):
    # NOTE: the report should be written into the sarif_retry_metadatas   
    sarif_metadata_output = SARIFMetadata(
        task_id=sarif_meta.task_id,
        sarif_id=sarif_meta.sarif_id,
        pdt_sarif_id=sarif_meta.pdt_sarif_id,
        pdt_task_id=sarif_meta.pdt_task_id,
        metadata=sarif_meta.metadata,
        assessment=Assessment.AssessmentCorrect if verdict == "TP" else Assessment.AssessmentIncorrect,
    )
    sarif_retry_metadata_path = os.getenv("SARIF_RETRY_METADATA", None)
    try:
        with open(sarif_retry_metadata_path, "w") as f:
            f.write(sarif_metadata_output.model_dump_json(indent=2))
        _l.info(f"Emitted SARIF assessment to {sarif_retry_metadata_path}")
    except Exception as e:
        _l.error(f"Failed to write SARIF assessment to {sarif_retry_metadata_path}: {e}")

class LLMLocalBudgetExceededError(Exception):
    """
    Exception raised when the local budget for LLM calls is exceeded.
    This is used to signal that the LLM should not be called anymore.
    """
    def __init__(self, message="Local budget for LLM calls exceeded."):
        super().__init__(message)
        self.message = message

    def __str__(self):
        return f"LLMLocalBudgetExceededError: {self.message}"
    
