import json
import os
import subprocess
from pathlib import Path
import tempfile
import time
from typing import List, Set, TypeAlias, Union

from coveragelib import Parser, log
from coveragelib.parsers.utils import ParsingError
from shellphish_crs_utils.models.oss_fuzz import LanguageEnum
from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject

from shellphish_crs_utils.utils import artiphishell_should_fail_on_error, safe_decode_string

class C_Indirect_PinTracer(Parser):
    HAS_INTERNAL_COMMAND = False
    HAS_EXTERNAL_PROCESSING = False
    HAS_VALUE_PARSER = False

    LANGUAGES = [LanguageEnum.c, LanguageEnum.cpp]

    def parse_values(self, oss_fuzz_project, coverage_path):
        # Just return the content of the file 
        with open(coverage_path, "rb") as infile:
            content = safe_decode_string(infile.read())
        return content.splitlines()

class C_Calltrace_PinTracer(Parser):
    HAS_INTERNAL_COMMAND = False
    HAS_EXTERNAL_PROCESSING = False
    HAS_VALUE_PARSER = True

    LANGUAGES = [LanguageEnum.c, LanguageEnum.cpp]

    def parse_values(self, oss_fuzz_project, coverage_path):
        # NOTE: the following awk command is removing unnecessary noise from the output 
        #  - __llvm functions
        # - profdata profiling functions (e.g., writeOneValueProfData)
        # NOTE: instead of parsing the json, let's use awk to remove unnecessary stuff (faster)
        
        # Create a temporary file to store the result of the awk command
        # with tempfile.NamedTemporaryFile(delete=True) as temp_file:
        #     # NOTE: removes everything before LLVMFuzzerTestOneInput
        #     AWK_CMD_ONE = r'''awk '/LLVMFuzzerTestOneInput/ {found=1} /__llvm_profile_write_file/ {exit} found' <COVERAGE_PATH>'''
        #     awk_cmd = AWK_CMD_ONE.replace("<COVERAGE_PATH>", str(coverage_path))
        #     # Execute the awk command and write the output to the temporary file
        #     subprocess.run(awk_cmd, shell=True, stdout=temp_file)

        #     # NOTE: keep only the FunctionName
        #     AWK_CMD_TWO = r'''awk -F '"FunctionName":"' '{split($2, arr, "\""); print arr[1]}' <COVERAGE_PATH>'''
        #     awk_cmd = AWK_CMD_TWO.replace("<COVERAGE_PATH>", temp_file.name)
        #     result = subprocess.run(awk_cmd, shell=True, capture_output=True, text=True)
        #     all_functions = result.stdout.splitlines()
        all_functions = []
        with open(coverage_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
            for l in lines:
                json_data = json.loads(l)
                data = json_data.get("Symbol", [])
                if "__llvm_profile_is_continuous_mode_enabled" in data[0]["FunctionName"]:
                    break
                all_functions.append((data[0]["FunctionName"]))
        assert len(all_functions) > 0, f"Error while parsing coverage report for PinTracer at {coverage_path}. No functions found. Ping @ubersandro/@degrigis"
        return all_functions

class C_Calltrace_Json_PinTracer(Parser):
    HAS_INTERNAL_COMMAND = False
    HAS_EXTERNAL_PROCESSING = False
    HAS_VALUE_PARSER = True

    LANGUAGES = [LanguageEnum.c, LanguageEnum.cpp]

    def parse_values(self, oss_fuzz_project, coverage_path):
        all_functions = []
        with open(coverage_path, "r", encoding="utf-8", errors="ignore") as f:
            all_functions = f.readlines()

        actual_covered_functions = []
        # heck you Ubersandro (by Lukas)
        if isinstance(all_functions[0], str):
            for x in all_functions:
                actual_covered_functions.append(json.loads(x))
        elif isinstance(all_functions[0], list):
            for f in all_functions[0]:
                actual_covered_functions.append(json.loads(f))
        else:
            assert False, "Unexpected format for all_functions | ping @ubersandro"
        
        assert len(actual_covered_functions) > 0, f"Error while parsing coverage report for PinTracer at {coverage_path}. No functions found. Ping @ubersandro/@degrigis"        
        
        return actual_covered_functions



class Java_Calltrace_Yajta(Parser):
    HAS_INTERNAL_COMMAND = False
    HAS_EXTERNAL_PROCESSING = False
    HAS_VALUE_PARSER = True

    LANGUAGES = [LanguageEnum.jvm]

    def parse_values(self, oss_fuzz_project: OSSFuzzProject, coverage_path: Union[Path, str]):
        # The following code is meant to be executed after the oss-fuzz-coverage script ran to perform
        # further processing.

        coverage_path = Path(coverage_path)
        # Check if the file exists
        if not os.path.exists(coverage_path):
            raise ParsingError(f"Error while parsing coverage report at {coverage_path}")

        with open(coverage_path, "r", encoding="utf-8", errors="ignore") as infile:
            calltrace = json.load(infile)

        return calltrace
