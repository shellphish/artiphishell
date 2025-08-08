from pathlib import Path
from typing import Dict, List, Optional
from pydantic import BaseModel, Field
from shellphish_crs_utils.models.base import ShellphishBaseModel

class TestGuyMetaData(ShellphishBaseModel):
    num_tests_passed: Optional[int] = Field(None, description="The number of tests that passed.")
    num_tests_failed: Optional[int] = Field(None, description="The number of tests that failed. Do not use it for patch verification as this is only for metadata puposes.")
    tests_status: Optional[Dict[str, List[str]]] = Field(None, description="The status of the tests. The key is 'passed' or 'failed' and the value is a list of tests that passed or failed.")
    # TODO: Add description
    true_build_src: Optional[str] = Field(None, description="The path to the directory in the container for the build source.")
    testing_dir_container_path: Optional[str] = Field(None, description="The path to the directory in the container where ....") 
    test_command_script: Optional[str] = Field(None, description="The bash script including the commands used to run the tests. If not provided, the tests were not found/run.")
    test_command_stdout: Optional[str] = Field(None, description="The stdout of the test command.")
    test_command_stderr: Optional[str] = Field(None, description="The stderr of the test command.")
    test_parser: Optional[Dict] = Field(None, description="The name and args for the tests output parser. If not provided, the tests were not found/run.")

    @property
    def test_available(self) -> bool:
        return (self.test_command_script is not None and self.num_tests_passed != 0)

class TestGuyLibMetaData(ShellphishBaseModel):
    success: bool = Field(False, description="Whether the patch is valid or not.")
    num_tests_passed: Optional[int] = Field(None, description="The number of tests that passed.")
    num_tests_failed: Optional[int] = Field(None, description="The number of tests that failed. Do not use it for patch verification as this is only for metadata puposes.")
    tests_status: Optional[Dict[str, List[str]]] = Field(None, description="The status of the tests. The key is 'passed' or 'failed' and the value is a list of tests that passed or failed.")
    test_command_stdout: Optional[str] = Field(None, description="The stdout of the test command.")
    test_command_stderr: Optional[str] = Field(None, description="The stderr of the test command.")

    @property
    def is_valid_patch(self) -> bool:
        return self.success

class TestGuyParserMetaData(ShellphishBaseModel):
    success: bool = Field(False, description="The parser was successfully able to parse the test results or not.")
    num_tests_passed: Optional[int] = Field(None, description="The number of tests that passed.")
    num_tests_failed: Optional[int] = Field(None, description="The number of tests that failed. Do not use it for patch verification as this is only for metadata puposes.")
    tests_status: Optional[Dict[str, List[str]]] = Field(None, description="The status of the tests. The key is 'passed' or 'failed' and the value is a list of tests that passed or failed.")

    @property
    def success(self) -> bool:
        return self.success
