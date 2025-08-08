import json
import logging
import os
import subprocess
import tempfile
from pathlib import Path
import random
import string
import yaml
import threading

from agentlib import tools
from shellphish_crs_utils.function_resolver import FunctionResolver
from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject
from QuickSeed.utils import find_absolute_path2

_l = logging.getLogger(__name__)

_thread_local = threading.local()

class ToolEnvironment:
    """
    A class to retrieve the source code of a class or method from the java project for LLM agent
    """
    def __init__(self, function_resolver: FunctionResolver, function_indexer_path: Path, function_json_dir: Path, project_source: Path, \
                 cp_root: Path, harness_name: str, fall_back_python_script: Path, oss_fuzz_build: OSSFuzzProject):
        self.DUPLICATE_TOOL_CALLS_GUARD_SIZE = 3
        # self.function_resolver = function_resolver
        self.function_indexer_path = function_indexer_path
        self.project_source = project_source
        self.function_json_dir = function_json_dir
        self.cp_root = cp_root
        self.harness_name = harness_name
        self.function_resolver = function_resolver
        self.fall_back_python_script = fall_back_python_script
        self.oss_fuzz_build = oss_fuzz_build

        self.last_retrieved_functions = []
    
    
    def __add_to_retrieve_function_history(self, requested_method_or_class: str):
        """
        Add a tool call to the history.
        This is used to avoid repeating the same tool call in a short period of time.
        """
        if len(self.last_retrieved_functions) > self.DUPLICATE_TOOL_CALLS_GUARD_SIZE:
            self.last_retrieved_functions = self.last_retrieved_functions[1:]
        self.last_retrieved_functions.append(requested_method_or_class)
    
    def invoke_retrieve_source(self, requested_method_or_class: str):
        if requested_method_or_class in self.last_retrieved_functions:
            return "Sorry, you have retrieved this method or class recently."
        else:
            # agentlib does not preserve the tool call results from the previous steps so we cannot really use the guard.
            self.__add_to_retrieve_function_history(requested_method_or_class)
            source = self.retrieve_source(requested_method_or_class)
        return source
    
    def retrieve_source(self, s: str):
        error_message = "Sorry, I cannot find the source code of the class. \
            It probably belongs to a library or a system class. \
            This means what you requested is irrelevant to the problem you are trying to solve.\
            Or this could becuase the method or class you requested does not exist."
        
        relative_file_path = None
        requested_class_name = None
        requested_method_name = None
        full_class_path = None

        if "." in s:
            parts = s.split(".")
            last_part = parts[-1]
            if last_part[0].isupper():
                requested_class_name = last_part
                full_class_path = "/".join(parts)
            else:
                requested_class_name = parts[-2]
                requested_method_name = parts[-1]
                try: 
                    keys = list(self.function_resolver.resolve_with_leniency(s))
                    return self.concatenate_source(keys)
                except Exception as e:
                    _l.error(f"Error resolving {s}: {e}")
                    return error_message
        else:
            if s[0].isupper():
                requested_class_name = s
            else:
                requested_method_name = s
                keys = list(self.function_resolver.find_by_funcname(requested_method_name))
                return self.concatenate_source(keys)
        # TODO: We should switch to funciton_resolver to find the source code
        # with open(self.function_indexer_path, "r") as f:
        #     indexer_data = yaml.safe_load(f)
        filename = requested_class_name + ".java"
        keys = list(self.function_resolver.find_by_filename(filename))
        if not keys:
            return error_message
        relative_file_path = self.function_resolver.get(keys[0]).target_container_path
        if relative_file_path is None:
            return error_message
        # try:
        resolved_path = self.oss_fuzz_build.artifacts_path(relative_file_path)
        # resolved_path = find_absolute_path2(self.project_source, relative_file_path)
        # if not resolved_path or not resolved_path.exists():
        #     resolved_path = find_absolute_path2(self.cp_root, relative_file_path)
        if not resolved_path or not resolved_path.exists():
            return error_message
        with open(resolved_path, "r") as f:
            return f.read()

    def concatenate_source(self, keys: list)-> str:
        source = ""
        for key in keys:
            source += self.function_resolver.get(key).code + "\n"
        return source
    
    def run_python_script_in_environment(self, script: str) -> str:
        """
        Run a python code you provided. And return stdout of the running script.
        Note that this python script does not have access to API to trigger crashes.

        :param script: The content of your python script
        :return: The stdout or stderr of the running script
        """

        fallback_script = self.fall_back_python_script
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(Path(tmpdir) / "llm_generated_script.py", "w") as f:
                f.write(script)
            _l.debug(f"Working at {tmpdir} to test llm generated script")
            try:
                p = subprocess.run(["python3", "llm_generated_script.py"], capture_output=True, text=True, errors="ignore",
                                timeout=30, cwd=tmpdir)
            except subprocess.TimeoutExpired:
                return "Timeout: the script takes too long to run."
            if p.returncode != 0:
                return p.stderr
            if fallback_script:
                random_string = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
                randome_name = f"gen_seed_{random_string}.py"
                with open(fallback_script / randome_name, "w") as f:
                    f.write(script)
            return p.stdout
        

    def clean_tool_call_history(self):
        self.last_tool_calls_performed = []


def create_llm_tools(tool_environment: ToolEnvironment) -> list:
    _thread_local.tool_environment = tool_environment
    return [run_python_code, retrieve_java_source]

@tools.tool
def run_python_code(script: str) -> str:
    """
    Run a python code you provided. And return stdout of the running script.
    Note that this python script does not have access to API to trigger crashes.

    :param script: The content of your python script
    :return: The stdout or stderr of the running script
    """
    return _thread_local.tool_environment.run_python_script_in_environment(script)

@tools.tool
def retrieve_java_source(requested_method_or_class: str) -> str:
    """
    Retrieve the source code of a class or method from the java project.

    :param requested_method_or_class: The name of the class or method. In the case of a method, please use `Class.method` format if you also know the class name. If not, just use the method name.
    :return: The source code of the class or method or an error message if we cannot find them.
    """
    return _thread_local.tool_environment.invoke_retrieve_source(requested_method_or_class)