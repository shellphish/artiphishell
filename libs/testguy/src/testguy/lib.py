#!/usr/bin/env python3

import yaml
import os
import logging
from pathlib import Path

from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject
from shellphish_crs_utils.models.crs_reports import RunImageResult
from shellphish_crs_utils.models.testguy import TestGuyMetaData, TestGuyLibMetaData, TestGuyParserMetaData

from .utils.helpers import execute_command_in_builder
from .utils.parsers import simple_parser, junit_parser, nginx_unit_tests_parser

class TestGuy:
    def __init__(self, **kwargs):
        # Global try except block to catch any errors during initialization
        try:
            # Store here all the stuff we got passed by the command line
            # see (testguy/run.py)
            self.kwargs = kwargs

            # Parsers map
            self.parsers = {
                "simple_parser": simple_parser,
                "junit_parser": junit_parser,
                "nginx_unit_tests_parser": nginx_unit_tests_parser
            }

            # testguy report
            self.testguy_report = TestGuyMetaData.model_validate(yaml.safe_load(open(self.kwargs['testguy_report_path'], 'r')))

            ### PATHS ###
            self.project_id = self.kwargs['project_id']
            self.project_path = Path(self.kwargs['project_path'])
            true_build_src = str(self.testguy_report.true_build_src)
            # project path in testguy container
            self.build_src = Path(self.project_path) / "artifacts" / "built_src" / true_build_src
            # project path in docker for LLM to work on
            self.build_src_docker = Path(self.testguy_report.testing_dir_container_path)

            print(f"Project path: {self.project_path}\n" \
                f"Project path build src: {self.build_src}\n" \
                f"Project path docker: {self.build_src_docker}")

            self.project = OSSFuzzProject(  
                                            project_id = self.project_id,
                                            oss_fuzz_project_path = Path(self.project_path),
                                            project_source = Path(self.build_src),
                                            use_task_service = self.kwargs['use_task_service']
                                        )
            if os.getenv('LOCAL_RUN') == 'True':
                self.project.build_builder_image()
                self.project.build_runner_image()
            
            self.init_success = True

        # For any errors that occur during initialization, set init_success to False
        except Exception as e:
            logging.error(f"🤡 Error initializing TestGuy: {e}")
            self.init_success = False

    def test(self) -> TestGuyLibMetaData:
        # If initialization failed, return a TestGuyLibMetaData object with success set to True
        # because we don't want to fail the whole pipeline
        if not self.init_success:
            logging.error("🤡 TestGuy initialization failed. Cannot run tests.")
            return TestGuyLibMetaData(success=True)

        test_result = TestGuyLibMetaData()
        
        # Run the 'test command' provided by the testguy report
        result: RunImageResult = execute_command_in_builder(
                                                            self.project, 
                                                            self.testguy_report.test_command_script, 
                                                            self.build_src, 
                                                            self.build_src_docker
                                                            )
        
        # Parse the result using the 'parser' provided by the testguy report
        self.kwargs['result'] = result
        self.kwargs['project_path'] = self.project_path
        self.kwargs['args'] = self.testguy_report.test_parser['args']
        
        parser = self.parsers[self.testguy_report.test_parser['type']]
        parsed_result: TestGuyParserMetaData = parser(**self.kwargs)

        # Store the parsed results in a TestGuyLibMetaData object
        test_result.num_tests_passed = parsed_result.num_tests_passed
        test_result.num_tests_failed = parsed_result.num_tests_failed
        test_result.tests_status = parsed_result.tests_status
        test_result.test_command_stdout = result.stdout.decode("utf-8")
        test_result.test_command_stderr = result.stderr.decode("utf-8")

        # Compare the parsed result with the testguy report results
        logging.info(f"📧 Original testguy report: {self.testguy_report.num_tests_passed} tests passed")
        logging.info(f"📧 New testguy report: {parsed_result.num_tests_passed} tests passed")
        
        if parsed_result.num_tests_passed >= self.testguy_report.num_tests_passed:
            test_result.success = True

        return test_result
