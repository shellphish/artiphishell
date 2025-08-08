import os
import re
import subprocess
import logging
import shutil
import networkx as nx
import shlex
import uuid
import hashlib
import yaml
import whatthepatch

from typing import List, Union
from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject
from shellphish_crs_utils.models.coverage import FUNCTION_INDEX_KEY, FunctionIndex
from shellphish_crs_utils.models.ranking import RankedFunction
from shellphish_crs_utils.utils import safe_decode_string
from shellphish_crs_utils.models.crs_reports import CrashingInputMetadata
from shellphish_crs_utils.models.target import HarnessInfo
from analysis_graph.models.harness_inputs import HarnessInputNode

from pathlib import Path
from functools import reduce

from discoveryguy.config import Config, DiscoverGuyMode, CRSMode

from .config import Config

log = logging.getLogger("discoveryguy.utils")
logger = log
import signal
from .analysis_graph_api import AnalysisGraphAPI
# DEFINE THESE AS GLOBAL SO THAT WE CAN KEEP TRACK OF WHAT WE HAVE SEEN IN THE PREV.RUNS
# need to keep track of functions we have seen so that we don't loop back to them
# seen = set()
# need to keep track of functions we haven't reached so that we can give feedback to LLM
# not_reached = set()

# KEEP THIS IN SYNC WITH
# https://github.com/shellphish-support-syndicate/artiphishell/blob/main/libs/crs-utils/src/shellphish_crs_utils/oss_fuzz/instrumentation/discoveryguy/Dockerfile.prebuild
AVAILABLE_PYTHON_PACKAGES = [
        "numpy",
        "fpdf2",
        "pillow",
        "requests",
        "scapy",
        "cryptography",
        "PyJWT",
        "bitstring",
        "Faker",
        "pyelftools",
        "pefile",
        "macholib",
        "construct",
        "protobuf",
        "pyminizip",
        "xtarfile",
        "vpydub",
        "soundfile",
        "moviepy",
        "opencv-python",
        "openpyxl",
        "python-docx",
        "pyOpenSSL"
]
#     def backup_crash_report(self, harness_bin_name, function_name, sink_index_key, analysis_report, script, crashing_output, report_no, attempt_no, status):
def timeout_handler(signum, frame):
    raise TimeoutError("Request timed out")

signal.signal(signal.SIGALRM, timeout_handler)

class CodeQLSourceLocation:
    def __init__(self, keyindex, file, func, line):
        self.keyindex = keyindex
        self.file = file
        self.func = func
        self.line = line

# NOTE: this class is a temporary solution to resolve sinks in different report.
#       The right way to do so is to use the SourceLocation provided by the FunctionResolver
#       However, as for now, that doesn't support the resolution of a filename + line number
#       which is in general exactly what we need here...
class CodeQLSourceLocationResolver:
    def __init__(self, func_resolver):
        self.func_resolver = func_resolver

    def resolve_file_and_loc(self, loc_file:str, loc_line:int):
        all_funcs_in_file:List[FUNCTION_INDEX_KEY] = list(self.func_resolver.find_by_filename(loc_file))

        if not all_funcs_in_file:
            return None

        codeql_loc:CodeQLSourceLocation = None
        for func_in_file in all_funcs_in_file:
            func_start, func_end = self.func_resolver.get_function_boundary(func_in_file)

            if loc_line >= func_start and loc_line <= func_end:
                loc_func:FunctionIndex = func_in_file
                function_info:FunctionIndex = self.func_resolver.get(func_in_file)
                if function_info.target_container_path:
                    codeql_loc = CodeQLSourceLocation(
                        keyindex=func_in_file,
                        file=str(function_info.target_container_path),
                        func=function_info.funcname,
                        line=loc_line
                    )
                    break

        return codeql_loc

class DiffResolver:
    def __init__(self, diff_file, func_resolver):
        self.func_resolver = func_resolver
        self.diff_file = diff_file
        with open(self.diff_file, "r") as f:
            self.diff_text = f.read()
        self.processed_results = False
        self.sinks = set()

    def get_sinks(self):
        if self.processed_results:
            return self.sinks
        try:
            for diff in whatthepatch.parse_patch(self.diff_text):
                loc_file = os.path.basename(diff.header.new_path)
                for sink_funckey in self.func_resolver.find_by_filename(loc_file):
                    sink_boundaries = self.func_resolver.get_function_boundary(sink_funckey)
                    for change in diff.changes:
                        if change.old != None:
                            if change.old >= sink_boundaries[0] and change.old <= sink_boundaries[1]:
                                self.sinks.add(sink_funckey)

        except Exception as e:
            logger.error(f"Error parsing diff file {self.diff_file}: {e}")

        self.processed_results = True
        self.sinks = list(self.sinks)

        return self.sinks


class HarnessFullInfo:
    def __init__(self, info_id, bin_name, func_key, code):
        self.func_key = func_key
        self.bin_name = bin_name
        self.info_id = info_id
        self.code = code

class HarnessResolver:
    def __init__(self, cp_debug:OSSFuzzProject, project_language, harness_infos:dict, func_resolver):
        self.cp_debug = cp_debug
        self.project_language = project_language
        self.harness_infos = harness_infos
        self.func_resolver = func_resolver
        self.harness_full_infos:List[HarnessFullInfo] = []
        for harness_id, harness_info in harness_infos.items():
            harness_index_key = self.cp_debug.get_harness_function_index_key(
                harness_info['cp_harness_name'],
                self.func_resolver
            )
            try:
                harness_file = self.cp_debug.get_harness_source_artifacts_path(harness_info['cp_harness_name'], self.func_resolver)
                with open(harness_file,"r") as f:
                    harness_code = f.read()
            except Exception as e:
                logger.error(f"Error reading harness file for {harness_info['cp_harness_name']}: {e}")
                if self.project_language == "c" or self.project_language == "c++":
                    harness_code = self._get_file_contents_from_index(harness_index_key)
                else:
                    harness_code = self.func_resolver.get_code(harness_index_key)[-1]
            hfi = HarnessFullInfo(harness_id, harness_info['cp_harness_name'], harness_index_key, harness_code)

            self.harness_full_infos.append(hfi)

    def get_harness_prefix_in_scope(self):
        if self.project_language == "c" or self.project_language == "c++":
            harness_prefix = "LLVM"
        else:
            harness_prefix = "fuzzerTest"

        return harness_prefix

    def get_all_harnesses(self):
        return self.harness_full_infos

    def get_harness_by_index(self, harness_func_key_index: FUNCTION_INDEX_KEY) -> HarnessFullInfo:
        """
        Get the harness information by its function index key.
        """
        tmp_harness_index_key = self.func_resolver.find_matching_index(scope="compiled", index=harness_func_key_index)
        for harness_info in self.harness_full_infos:
            if harness_info.func_key == tmp_harness_index_key:
                return harness_info
        return None

    def get_harness_info_by_id(self, harness_info_id: str) -> HarnessInfo:
        """
        Get the harness information by its info ID.
        """
        if harness_info_id not in self.harness_infos:
            return None
        return HarnessInfo.model_validate(self.harness_infos[harness_info_id])

    def _get_file_contents_from_index(self, index) -> str:

        relative_file_path = str(self.func_resolver.get(index).target_container_path).lstrip("/")
        if not relative_file_path.startswith("src/"):
            return ""

        # NOTE: change the first occurence of src/ to built_src/
        #       this is the format we expect and create in the the run.sh scripts.
        relative_file_path = relative_file_path.replace("src/", "built_src/", 1)

        # NOTE: discoveryGuy can look anywhere (even in paths that are not in scope).
        #       this is because it doesn't need to modify the files.
        #       /artifacts/built_src is guaranteed to exists!
        full_file_path = os.path.join(self.cp_debug.project_path, "artifacts", relative_file_path)

        # Check if the path exists
        if not os.path.exists(full_file_path):
            logger.error(f"File {full_file_path} does not exist!")
            return ""

        with open(full_file_path, 'r') as file:
            file_content = file.read()

        return file_content



#################################################
# NOTE, Jimmy's magic 🪄: simplify the paths
#################################################
class JimmyMagicPathSimplifier:
    def __init__(self, analysis_graph_api:AnalysisGraphAPI, harness_resolver: HarnessResolver, func_resolver, diff_file):
        self.analysis_graph_api = analysis_graph_api
        self.harness_resolver = harness_resolver
        self.func_resolver = func_resolver
        self.diff_file = diff_file
        self.sink_graphs = []

    def _get_diff(self, function_index: str) -> str:
        with open(self.diff_file, "r") as f:
            diff_text = f.read()

        # path = str(self.func_resolver.get_focus_repo_relative_path(function_index))
        path = str(self.func_resolver.get(function_index).target_container_path)
        name = self.func_resolver.get_funcname(function_index)
        boundary = self.func_resolver.get_function_boundary(function_index)
        ALL_TEXT = ""
        flag = 0
        for diff in whatthepatch.parse_patch(diff_text):
            if  diff.header.new_path not in path:
                continue
            match = re.split(r"(@@ -\d+,\d+ \+\d+,\d+ @@)", diff.text)
            results_tmp = {}
            text = match[0]
            for snippet in match[1:]:
                if snippet.startswith("@@"):
                    match_header = re.match(r"@@ -(\d+),\d+ \+(\d+),(\d+) @@", snippet)
                    base_line = int(match_header.group(1))
                    target_line = int(match_header.group(2))
                    changed_lines = int(match_header.group(3))
                    if  boundary[0]>target_line+changed_lines or boundary[1]<target_line:
                        should_include = False
                    else:
                        should_include = True
                        text += (snippet+match[match.index(snippet) + 1])+ "\n"
                        flag = 1
                        # print("Found diff for function %s in file %s" % (name, path))

                    results_tmp[snippet] = {
                        "target_line": target_line,
                        "base_line": base_line,
                        "snippet": snippet + match[match.index(snippet) + 1],
                        "include": should_include
                    }
            ALL_TEXT += text

        if flag == 0:
            log.info("Can't find diff for function %s in file %s" % (name, path))
            return f"THE CODE OF  `{name}` WAS NOT CHANGED IN THE DIFF FILE"
        else:
            log.info("Found diff for function %s in file %s" % (name, path))
            return ALL_TEXT

    def get_nodes(self, reached_harnesses, sink_index_key, with_path:bool=False) -> str:
        if with_path:
            for _, harness in reached_harnesses.items():
                try:
                    signal.alarm(10)  # 10 second timeout
                    paths = self.analysis_graph_api.get_paths_from_harness_to_sink(
                        harness.bin_name,
                        sink_index_key
                    )
                    signal.alarm(0)  # Cancel alarm on success
                except TimeoutError:
                    print("Analysis Graph request timed out!")
                    continue
                except Exception as e:
                    signal.alarm(0)  # Make sure to cancel alarm on other exceptions
                    print(f"Other error: {e}")
                    continue
                try:
                    for path in paths:
                        tmp_relations = path[0].relationships
                        G = nx.DiGraph()
                        for rel in tmp_relations:
                            G.add_edge(rel.start_node().identifier, rel.end_node().identifier)
                        self.sink_graphs.append(G)
                except Exception as e:
                    logger.error(f"Error in get_paths_from_harness_to_sink:{sink_index_key}, {e}")
                    continue
            try:
                G_merged = reduce(nx.compose, self.sink_graphs)
                old_nodes, G_without_cycle = reduce_cycle(G_merged)
                G_optimized = find_functions_with_one_caller_and_one_callee(G_without_cycle, list(reached_harnesses.keys()), sink_index_key)
                new_nodes, G_optimized_without_cycle = reduce_cycle(G_optimized)
                logger.info(f" 🚰🛣️ Found {len(new_nodes)} nodes in the optimized graph for {sink_index_key} with {len(reached_harnesses)} harnesses, before there are {len(old_nodes)} nodes in the graph.")
            except Exception as e:
                logger.error(f"Error in reduce_cycle or find_functions_with_one_caller_and_one_callee: {e}")
                new_nodes = []


            # NOTE: Get the nodes for different modes
            if Config.crs_mode == CRSMode.FULL:
                nodes = []
                for key in new_nodes:
                    if key == "__connector__":
                        logger.info("Resolving __connector__ ...")
                        name = "__connector__"
                        code = "This is a connector node, not an actual function. It abstracts a group of intermediate functions that link otherwise disjoint paths. The functions that are in the cluster are: \n"
                        # import ipdb; ipdb.set_trace()
                        functions_in_cluster = set(old_nodes)-set(new_nodes)
                        for index in functions_in_cluster:
                            tmp_name = self.func_resolver.get_funcname(index)
                            code += f" - {tmp_name} \n"
                    else:
                        code = self.func_resolver.get_code(key)[-1]
                        name = self.func_resolver.get_funcname(key)
                    nodes.append({
                        "key": key,
                        "code": code,
                        "name": name
                    })
            else:
                # NOTE: in this case we also include the diff for each function in the path
                nodes = []
                for key in new_nodes:
                    if key == "__connector__":
                        logger.info("Resolving __connector__ ...")
                        code = "This is a connector node, not an actual function. It abstracts a group of intermediate functions that link otherwise disjoint paths. The functions that are in the cluster are: "
                        functions_in_cluster = set(old_nodes)-set(new_nodes)
                        diff = "In this cluster, the diff for these functions are in the cluster are: \n"
                        name = "__connector__"
                        for index in functions_in_cluster:
                            tmp_name = self.func_resolver.get_funcname(index)
                            code += f" - {tmp_name} \n"
                            tmp_diff = self._get_diff(index)
                            diff += f" - {tmp_name} \n"
                            diff += tmp_diff

                    else:
                        code = self.func_resolver.get_code(key)[-1]
                        name = self.func_resolver.get_funcname(key)
                        diff = self._get_diff(key)

                    nodes.append({
                        "key": key,
                        "code": code,
                        "name": name,
                        "diff": diff
                    })
        else:
            # NOTE: in this case we do not have a path from the harness to the sink
            #       so we just use the function itself  and the harnesses as the node
            nodes = []
            for harness_func_key, harness in list(reached_harnesses.items()):
                code = self.func_resolver.get_code(harness_func_key)[-1]
                name = self.func_resolver.get_funcname(harness_func_key)
                nodes.append({
                    "key": harness_func_key,
                    "code": code,
                    "name": name,
                })

        return nodes

class SeedDropperManager:

    def __init__(self, dg_id, project_name, harness_infos: dict, backup_seeds_vault: str, report_dir: str, crash_dir_pass_to_pov:str, crash_metadata_dir_pass_to_pov:str):
        self.dg_id = dg_id
        self.project_name = project_name
        self.backup_seeds_vault = backup_seeds_vault
        self.report_dir = report_dir
        os.makedirs(self.report_dir, exist_ok=True)
        self.fuzzers_sync_base = "/shared/fuzzer_sync/"
        self.crash_metadata_dir_pass_to_pov = crash_metadata_dir_pass_to_pov
        self.crash_dir_pass_to_pov = crash_dir_pass_to_pov
        self.harness_infos = harness_infos

        # This is a dict that maps harness IDs to their corresponding sync folder paths and the progressive seed id
        # e.g.,
        # {
        #   'b29dddfb27659dd19b8e75ba3c727d1f' : ('/shared/fuzzer_sync/nginx-smtp_harness-b29dddfb27659dd19b8e75ba3c727d1f/sync-discoguy/queue/', 0)
        # }
        # NOTE: the seed id MUST be progressive within the same folder,
        #       the format for the seed id is 0 -> 000000, 1 -> 000001, etc...
        self.harness_id_to_folder = {}
        for harness_id, harness_info in harness_infos.items():
            harness_name = harness_info['cp_harness_name']
            random_id = os.urandom(16).hex()[0:10]
            new_sync_folder_name = f"{project_name}-{harness_name}-{harness_id}/sync-discoguy-{random_id}/queue/"
            new_sync_folder_name = self.fuzzers_sync_base + new_sync_folder_name
            log.info(f"Creating sync folder: {new_sync_folder_name}")
            # Create the directory if it does not exist
            shutil.os.makedirs(new_sync_folder_name, exist_ok=True)
            self.harness_id_to_folder[harness_id] = (new_sync_folder_name, 0)

    def add_seed(self, harness_id, seed_path):

        if harness_id not in self.harness_id_to_folder:
            log.error(f" 😶‍🌫️ harness ID {harness_id} not found in harness_id_to_folder")
            return False

        sync_folder, seed_id = self.harness_id_to_folder[harness_id]
        new_seed_name = f"id:{seed_id:06d},src:discoveryguy-{self.dg_id},reason:llm"
        new_seed_path = os.path.join(sync_folder, new_seed_name)

        # Finally copy the seed file to the new path
        try:
            log.info(f"Copying seed from {seed_path} to {new_seed_path}")
            shutil.copy(seed_path, new_seed_path)

            # Increment the seed ID for the next seed
            self.harness_id_to_folder[harness_id] = (sync_folder, seed_id + 1)
            return True

        except Exception as e:
            log.error(f"Failed to copy seed {seed_path} to {new_seed_path}: {e}")
            return False

    def backup_crash_report(self, harness_bin_name, function_name, sink_index_key, analysis_report, script, crashing_output, report_no, attempt_no, id, status):
        report_dir = os.path.join(self.report_dir, f"{function_name}_{harness_bin_name}_report{report_no+1}_script{attempt_no+1}_{status}_{id}")
        try:
            log.info(f"📜 Writing crash report to {report_dir}")
            with open(report_dir, "w") as f:
                yaml.safe_dump({
                    "sink_index_key": sink_index_key,
                    "harness_bin_name": harness_bin_name,
                    "sink_function_name": function_name,
                    "analysis_report": analysis_report,
                    "script": script,
                    "crashing_output": crashing_output,
                    "analysis_report_no": report_no+1,
                    "seed_generation_no": attempt_no+1,
                    "status": status
                }, f, default_flow_style=False, sort_keys=False)
            return True
        except Exception as e:
            log.error(f"😭 Failed to write crash report to {report_dir}: {e}")
            return False

    def backup_seed(self, harness_bin_name, function_name, seed_path, report_no, attempt_no, id, status):
        # Also copy the seed to the backup vault
        try:
            new_seed_path = os.path.join(self.backup_seeds_vault, f"{function_name}_{harness_bin_name}_report{report_no+1}_script{attempt_no+1}_{status}_{id}")
            shutil.copy(seed_path, new_seed_path)
            return True
        except Exception as e:
            log.error(f"Failed to copy seed {seed_path} to backupv vault {new_seed_path}: {e}")
            return False

    def send_seed_to_povguy(self, crashing_harness_info_id:str, crashing_seed_at:Union[str,Path]):
        if type(crashing_seed_at) == str:
            generated_seed_path = Path(crashing_seed_at)

        # Make sure that path exists
        assert generated_seed_path.exists(), f"Crashing seed path {generated_seed_path} does not exist!"
        md5name = hashlib.md5(generated_seed_path.read_bytes()).hexdigest()
        seed_file = Path(self.crash_dir_pass_to_pov) / md5name
        seed_meta_file = Path(self.crash_metadata_dir_pass_to_pov) / md5name

        logger.info("Passing crashing seed to povguy ➡️🌱👷🏻‍♂️")
        shutil.copy(generated_seed_path, seed_file)

        for harness_info_id, harness_info in self.harness_infos.items():
            if crashing_harness_info_id == harness_info_id:
                val = dict(harness_info)
                val['harness_info_id'] = harness_info_id
                val['fuzzer'] = 'discoveryguy'
                harness_data = CrashingInputMetadata.model_validate(val)
                with open(seed_meta_file, "w") as f:
                    yaml.safe_dump(harness_data.model_dump(mode='json'), f, default_flow_style=False, sort_keys=False)
                break
        else:
            logger.critical(f"[FIXME] Crashing harness info ID {crashing_harness_info_id} not found in harness infos!")

    def send_seed_to_analysis_graph(self, crashing_harness_info_id, crashing_harness_info, crash_txt, is_crashing):

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
            logger.warning(f"👀 Failed to create harness input node in analysis graph: {e}")
            crashing_input_id = None

        if crashing_input_id != None:
            try:
                cid = crashing_input_id[1].identifier
                return cid
            except Exception as e:
                return None
        else:
            return None

# grab vulnerable function from local data
def get_vuln_function(vuln_code):
    path = "discoveryguy/data/vulncode/local/" + vuln_code + ".c"
    with open(path, "r") as file:
        vuln = file.read()
        return vuln

def get_stacktrace(PoVReportNodeData):
    stacktrace = []
    for call_location in PoVReportNodeData['dedup_crash_report']['stack_traces']['main']['call_locations']:
        depth = call_location['depth']
        trace_line = call_location['trace_line']
        stacktrace.append(f"{depth} {trace_line}\n")
    stacktrace = ''.join(stacktrace)
    return stacktrace


def apply_patch_source(patch: str, source_root: str):
    """
    Applies the patch to the source code in the given source root directory.
    The patch is expected to be in unified diff format.
    """
    patch_file = Path(source_root) / "patch.diff"
    with open(patch_file, 'w') as f:
        f.write(patch)

    # Apply the patch using git and pring the output
    if not os.path.exists(source_root):
        raise ValueError(f"Source root directory does not exist: {source_root}")
    if not os.path.isdir(source_root):
        raise ValueError(f"Source root is not a directory: {source_root}")
    if not os.path.exists(patch_file):
        raise ValueError(f"Patch file does not exist: {patch_file}")
    if not os.path.isfile(patch_file):
        raise ValueError(f"Patch file is not a file: {patch_file}")
    # Use git apply to apply the patch
    # Check if the patch was applied successfully
    result = subprocess.run(
        ["git", "-C", source_root, "apply", "--check", str(patch_file)],
        capture_output=True,
        text=True
    )
    if result.returncode != 0:
        raise ValueError(f"Failed to apply patch: {result.stderr.strip()}")
    # Now apply the patch
    result = subprocess.run(
        ["git", "-C", source_root, "apply", str(patch_file)],
        capture_output=True,
        text=True
    )
    if result.returncode != 0:
        raise ValueError(f"Failed to apply patch: {result.stderr.strip()}")
    logger.info(f"Patch applied successfully to {source_root}")
    # Clean up the patch file
    patch_file.unlink(missing_ok=True)
    return source_root

# using github to get vulnerable commit (more complex than just giving the vulnerable function)
def get_vuln_commit(repo, commit_hash):
    # Checkout the specific commit
    repo.git.checkout(commit_hash)

    # Get the commit object
    commit = repo.commit(commit_hash)

    # Get the diff for the commit
    diffs = (
        commit.diff(commit.parents[0], create_patch=True)
        if commit.parents
        else commit.diff(None)
    )  # Handle initial commit
    total_diff = ""
    for diff in diffs:
        # Handle different scenarios for diffs
        if diff.a_path and diff.b_path:
            header = f"File: {diff.a_path} -> {diff.b_path}\n"
        elif diff.a_path:
            header = f"File deleted: {diff.a_path}\n"
        elif diff.b_path:
            header = f"File added: {diff.b_path}\n"
        else:
            header = "Unknown change\n"
        total_diff += (
            header
            + diff.diff.decode("utf-8", errors="replace")
            + "\n"
            + "-" * 80
            + "\n"
        )
    with open("git_diff.txt", "w") as file:
        file.write(total_diff)
    return total_diff


# run a python script
def run_script(input_path, output_path):
    try:
        p = subprocess.run(
            ["python3", input_path],
            capture_output=True,
            text=True,
            errors="ignore",
            cwd=output_path,
            timeout=5,
        )
        if p.returncode != 0:
            log.error("error occured %s when running script %s", p.stderr, input_path)
            return False
        else:
            return True
    except Exception as e:
        log.error(
            "error occured %s when running script %s", e, input_path, exc_info=True
        )
        return False


def get_files(dir_path):
    all_files = ""
    for root, dirs, files in os.walk(dir_path, topdown=True):
        code_list = [item for item in files if ".c" in item or ".h" in item]
        if len(code_list) > 0:
            all_files += "folder: " + root.replace(dir_path, "") + "\n"
            # print (dirs)
            all_files += "files: " + str(code_list) + "\n"
            all_files += "--------------------------------\n"

    log.debug(all_files)
    return all_files
    # return os.walk(dir_path)

def translate_path(resolver, path):
    regex = r'([^/]+\.(?:c|cc|cpp|h|hpp)):\d+'
    match = re.search(regex, path)
    if not match:
        return None
    match = match.group()  # can do this because there should only be ONE match
    match_split = match.split(":")
    file_name = match_split[0]

    # handle the harnesses seperately?
    if "harness.cc" in file_name:
        id = resolver.find_by_funcname("LLVMFuzzerTestOneInput")
        for i in id:
            if file_name in i:
                return i

    line_num_match = file_name + ":" + str(int(match_split[1])-1)
    id = resolver.find_by_filename(file_name)
    for i in id:
        if line_num_match in i:
            return i
    return None

def rank_functions(functions:List[FunctionIndex], func_ranking):
    function_lookup = {item['function_index_key']: item for item in func_ranking['ranking']}

    def get_rank(function_key):
        if function_key in function_lookup:
            return function_lookup[function_key]['rank_index']
        else:
            return float('inf')  # Items not in the ranking go to the end

    # Create pairs of (function_key, rank) and sort by rank
    function_rank_pairs = [(function_key, get_rank(function_key)) for function_key in functions]
    return sorted(function_rank_pairs, key=lambda x: x[1])


def continuous_single_caller_subgraph(G, start_nodes):
    """Builds a subgraph of all continuous single-caller paths starting from each node."""
    subgraph = nx.DiGraph()

    for start in start_nodes:
        if start not in G:
            continue

        current = start
        while True:
            successors = list(G.successors(current))
            if len(successors) != 1:
                break

            next_node = successors[0]
            if next_node not in G:
                break

            preds = list(G.predecessors(next_node))

            # Add edge if valid
            if len(preds) == 1 or all(p in start_nodes for p in preds):
                subgraph.add_edge(current, next_node)
                current = next_node
            else:
                break
    return subgraph

def continuous_single_callee_subgraph(G, end_node):
    """Builds a subgraph ending at end_node with continuous single-callee chains."""
    subgraph = nx.DiGraph()

    current = end_node

    while True:
        predecessors = list(G.predecessors(current))
        if len(predecessors) != 1:
            break

        prev_node = predecessors[0]
        if len(list(G.successors(prev_node))) == 1:
            subgraph.add_edge(prev_node, current)
            current = prev_node
        else:
            break

    return subgraph

def find_functions_with_one_caller_and_one_callee(G, start_nodes, end_node):
    """Finds functions with one caller and one callee."""
    caller_subgraph = continuous_single_caller_subgraph(G, start_nodes)
    callee_subgraph = continuous_single_callee_subgraph(G, end_node)

    # Optionally combine both:
    combined = nx.compose(caller_subgraph, callee_subgraph)

    # Get tip of caller chain (nodes with out_degree == 0)
    caller_tips = [n for n in caller_subgraph.nodes if caller_subgraph.out_degree(n) == 0]
    # Get head of callee chain (nodes with in_degree == 0)
    callee_heads = [n for n in callee_subgraph.nodes if callee_subgraph.in_degree(n) == 0]

    # If already connected, no need to add dummy node
    connected = any(nx.has_path(combined, u, v) for u in caller_tips for v in callee_heads)
    if connected:
        return combined

    # Add a dummy node to connect them
    connector_node = "__connector__"
    combined.add_node(connector_node)
    # import ipdb; ipdb.set_trace()
    # Connect dummy from each caller tip to it, and from it to each callee head
    for u in caller_tips:
        if u not in start_nodes:
            combined.add_edge(u, connector_node)
    for v in callee_heads:
        if v not in start_nodes:
            combined.add_edge(connector_node, v)

    return combined

def reduce_cycle(G):
    if nx.is_directed_acyclic_graph(G):
        nodes = list(nx.topological_sort(G))
    else:
        while True:
            try:
                cycle = nx.find_cycle(G)
                print(f"Removing edge from cycle in old nodes: {cycle[0]}")
                G.remove_edge(*cycle[0])
            except nx.NetworkXNoCycle:
                print("No cycle found, proceeding with topological sort.")
                break
        nodes = list(nx.topological_sort(G))
    return nodes, G




def do_grep(context, project_source, expression):
    src_dir = Path(project_source)
    cmd = [
        'grep',
        '-C', str(context),
    ]
    cmd += [
        '--exclude-dir=' + './aflplusplus',
        '--exclude-dir=' + './honggfuzz',
        '--exclude-dir=' + './libfuzzer',
        '--exclude-dir=' + './shellphish',
    ]
    if context == 0:
        options = "-rniE"
    else:
        options = "-rhiE"

    cmd += [
        options,
        expression,
        "--",
        '.'
    ]

    cmd_serialized1 = shlex.join(cmd)
    log.info("Running: " + repr(cmd_serialized1))
    p1 = subprocess.Popen(cmd, cwd=project_source, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout1, stderr1 = p1.communicate()
    stdout1 = safe_decode_string(stdout1)
    return stdout1


def show_lines(project_source, file_path, line_no, context):
    file_path = file_path.lstrip('/')
    full_file_path = os.path.join(project_source, file_path)
    try:
        with open(full_file_path, 'r') as file:
            file_context = file.read()
        file_lines_tot = len(file_context.splitlines())
        begin_line = max(0, line_no - context)
        end_line = min(file_lines_tot, line_no + 2 * context)
        file_lines_in_scope = file_context.splitlines()[begin_line:end_line]
        if len(file_lines_in_scope) == 0 or file_lines_in_scope[1].startswith("import") or file_lines_in_scope[1].startswith("#include"):
            return ""
        lines = '\n'.join(file_lines_in_scope)
        return lines
    except Exception as e:
        log.warning(f"Error reading file {full_file_path}: {e}")
        return ""



def symbol_mutator(expression: str):
    """
    Mutate the expression to produce a list of valid symbols for the lookup_symbol tool.

    Args:
        expression (str): Input expression (maybe regex or string) to mutate.

    Returns:
        list[str]: List of mutated symbols suitable for lookup_symbol.
    """
    mutations = set()  # Use set to avoid duplicates

    # Add the original expression
    mutations.add(expression.strip())

    # Split by common delimiters and process each part
    parts = re.split(r'[\s\.\-\>\<\(\)\[\]\{\}\,\;\:\=\+\*\/\\\|\&\!\@\#\$\%\^\~\`]+', expression)
    parts = [part.strip() for part in parts if part.strip()]

    # Add individual parts
    for part in parts:
        if part:
            mutations.add(part)

    # Handle object -> member patterns
    arrow_patterns = re.findall(r'(\w+)\s*->\s*(\w+)', expression)
    for obj, member in arrow_patterns:
        mutations.add(f"{obj}->{member}")
        mutations.add(f"{obj} -> {member}")
        mutations.add(f"{obj}.{member}")
        mutations.add(f"->{member}")
        mutations.add(f"-> {member}")
        mutations.add(f".{member}")
        mutations.add(member)
        mutations.add(obj)

    # Handle dot notation patterns
    dot_patterns = re.findall(r'(\w+)\.(\w+)', expression)
    for obj, member in dot_patterns:
        mutations.add(f"{obj}.{member}")
        mutations.add(f"{obj}->{member}")
        mutations.add(f"{obj} -> {member}")
        mutations.add(f".{member}")
        mutations.add(f"->{member}")
        mutations.add(f"-> {member}")
        mutations.add(member)
        mutations.add(obj)

    # Handle function call patterns
    func_patterns = re.findall(r'(\w+)\s*\(', expression)
    for func in func_patterns:
        mutations.add(func)
        mutations.add(f"{func}(")
        mutations.add(f"def {func}")
        mutations.add(f"function {func}")

    # Handle assignment patterns
    assign_patterns = re.findall(r'(\w+)\s*=', expression)
    for var in assign_patterns:
        mutations.add(var)
        mutations.add(f"{var} =")
        mutations.add(f"{var}=")

    # Handle class/struct member access patterns
    class_patterns = re.findall(r'(\w+)::(\w+)', expression)
    for cls, member in class_patterns:
        mutations.add(f"{cls}::{member}")
        mutations.add(f"{cls}.{member}")
        mutations.add(f"{cls}->{member}")
        mutations.add(member)
        mutations.add(cls)

    # Handle array/index patterns
    array_patterns = re.findall(r'(\w+)\[', expression)
    for arr in array_patterns:
        mutations.add(arr)
        mutations.add(f"{arr}[")

    # Handle template/generic patterns
    template_patterns = re.findall(r'(\w+)<', expression)
    for tmpl in template_patterns:
        mutations.add(tmpl)
        mutations.add(f"{tmpl}<")

    # Handle quoted strings - extract content
    quoted_patterns = re.findall(r'["\']([^"\']+)["\']', expression)
    for content in quoted_patterns:
        mutations.add(content)
        mutations.add(f'"{content}"')
        mutations.add(f"'{content}'")

    # Handle regex-like patterns - extract meaningful parts
    if re.search(r'[\[\]\(\)\{\}\|\\\^\$\*\+\?]', expression):
        # Try to extract word patterns from regex
        word_parts = re.findall(r'\w+', expression)
        for word in word_parts:
            if len(word) > 1:  # Skip single characters
                mutations.add(word)

    # Handle camelCase and snake_case variations
    for part in parts:
        if part:
            # Convert camelCase to snake_case
            snake_case = re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', part).lower()
            if snake_case != part:
                mutations.add(snake_case)

            # Convert snake_case to camelCase
            camel_case = re.sub(r'_([a-z])', lambda m: m.group(1).upper(), part)
            if camel_case != part:
                mutations.add(camel_case)

            # Add PascalCase variant
            pascal_case = part[0].upper() + part[1:] if part else ""
            if pascal_case != part:
                mutations.add(pascal_case)

    # Remove empty strings and very short strings that might cause noise
    mutations = {m for m in mutations if m and len(m.strip()) > 0}

    # Convert back to list and sort for consistent output
    return sorted(list(mutations))


## Fuzzing stuff goes here
def run_fuzzer(project, harness_info ,crashing_seeds_path, timeout=300, print_output=False):
    """
    Run the LibFuzzer fuzzer on the given harness with the provided crashing seeds.
    This function sets up the necessary directories and command to run LibFuzzer.
    Args:
        project (OSSFuzzProject): The OSSFuzzProject object for the correct build.
        harness_info (dict): The harness information dictionary containing the harness binary path.
        crashing_seeds_path (str or Path): The path to the directory containing crashing seeds.
        timeout (int): The timeout for the fuzzer run in seconds.
        print_output (bool): Whether to print the output of the fuzzer run.
    Returns:
        str: The unique identifier for the fuzzer run (fuzzer UID).
    """
    workdir = Path(project.artifacts_dir_work)
    fuzzer_uid = hashlib.sha1(os.urandom(32)).hexdigest()
    # command_file_name = f"cmd_{fuzzer_uid}_fuzz.sh"
    # command_file = workdir.joinpath(command_file_name)

    corpus_dir = workdir.joinpath(f"dg-{fuzzer_uid}", "corpus")
    corpus_dir.mkdir(parents=True, exist_ok=True)

    crashes_dir = workdir.joinpath(f"dg-{fuzzer_uid}", "crashes")
    crashes_dir.mkdir(parents=True, exist_ok=True)

    sync_dir = workdir.joinpath(f"dg-{fuzzer_uid}", "sync")
    sync_dir.mkdir(parents=True, exist_ok=True)

    if isinstance(crashing_seeds_path, str):
        crashing_seeds_path = Path(crashing_seeds_path)

    if crashing_seeds_path.is_dir() and crashing_seeds_path.exists():
        log.info(f"Copying crashing seeds from {crashing_seeds_path} to corpus directory {corpus_dir}")
        shutil.copytree(crashing_seeds_path, corpus_dir, dirs_exist_ok=True)

    # harness_path = harness_info['cp_harness_binary_path']
    harness_name = harness_info['cp_harness_name']

    _ = project.fuzz_harness(
        harness_name,
        sync_dir, # This is not important for this run just filling it here
        f"dg-{fuzzer_uid}",
        "libfuzzer",
        "address",
        [],
        {},
        True,
        True,
        True,
        f"/work/dg-{fuzzer_uid}/corpus",
        f"-artifact_prefix=/work/dg-{fuzzer_uid}/crashes/",
        timeout=timeout
    )

    # NOTE: Lukas said this is not allowed and said its gonna break.
    # Now lets format the libfuzzer command
    # cmd = f"/{harness_path} /work/dg-{fuzzer_uid}/corpus -artifact_prefix=/work/dg-{fuzzer_uid}/crashes/"
    # with open(command_file, "w") as f:
        # f.write("#!/bin/bash\n")
        # f.write(cmd)
    # command_file.chmod(755)  # Make the script executable
    #
    # _ = project.runner_image_run(f'/work/{command_file_name}',timeout=timeout, print_output=print_output)
    # This returns the fuzzer UID which is used to identify the fuzzer run
    return fuzzer_uid
