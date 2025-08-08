import os
import re
import logging
from typing import List, Tuple, Dict
from pathlib import Path

from .utils.helpers import execute_command_in_builder, get_build_src_c
from .utils.llm_helpers import check_test_command_output
from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject
from shellphish_crs_utils.models.crs_reports import RunImageResult
from shellphish_crs_utils.models.testguy import TestGuyMetaData

class Tester4C:
    def __init__(self, **kwargs):
        self.kwargs = kwargs
        
        ### PATHS ###
        self.project_path = Path(self.kwargs['project_path'])
        # dynamic path to the project source code
        self.potential_true_build_srcs = get_build_src_c(self.project_path, self.kwargs['compile_cmd_path'])
        
        ### TEST COMMANDS ###
        self.test_cmds_exps = {
            'make': {
                        'cmd': ['make test', 'make all test'],
                        'exp': ['No rule to make target', 'No rule to make target `test`']
                    },
            'cmake': {
                        'cmd': ['ctest --test-dir build', 'bin/unit'],
                        'exp': ['No tests were found', 'No test configuration file found']
                    },
            'prove': {
                        'cmd': ['prove .'],
                        'exp': []
                    }
        }

    def test_parser(self, result: RunImageResult, tag: str) -> Tuple[int, List[str]]:
        num_tests_passed = 0
        stdout = result.stdout.decode("utf-8")
        stderr = result.stderr.decode("utf-8")
        status = []

        for line in stdout.split("\n"):
            if tag in line:
                num_tests_passed += 1
                status.append(line)
        
        for line in stderr.split("\n"):
            if tag in line:
                num_tests_passed += 1
                status.append(line)
        
        return num_tests_passed, status

    def nginx_unit_tests_parser(self, result: RunImageResult) -> Tuple[int, int, Dict[str, List[str]]] | None:
        stdout = result.stdout.decode("utf-8")
        stderr = result.stderr.decode("utf-8")
        
        # 1) Check if the test summary report is present in the stdout or stderr
        marker = "Test Summary Report\n-------------------"
        if marker in stdout:
            report = stdout.split(marker)[1].strip()
        elif marker in stderr:
            report = stderr.split(marker)[1].strip()
        else:
            return None
        
        # 2) Parse the test summary report
        num_tests_passed = 0
        num_tests_failed = 0
        tests_status = {'passed': [], 'failed': []}

        test_file_regex = re.compile(r'^\./([\w_\.]+)\s+\(Wstat: \d+ Tests: (\d+) Failed: (\d+)\)')
        failed_test_regex = re.compile(r'\s*Failed\s*(?:tests|test):\s*(.+)')

        report_lines = report.split('\n')
        for i, line in enumerate(report_lines):
            # Match test file line
            file_match = test_file_regex.match(line)
            if file_match:
                test_file = file_match.group(1)
                total_tests = int(file_match.group(2))
                failed_tests = int(file_match.group(3))
                
                # Determine failed test list
                failed_test_list = []
                if failed_tests > 0:
                    # Look for failed tests in the next line
                    if i + 1 < len(report_lines):
                        failed_tests_match = failed_test_regex.match(report_lines[i + 1])
                        if failed_tests_match:
                            failed_test_numbers = failed_tests_match.group(1)
                            try:
                                for part in failed_test_numbers.split(','):
                                    part = part.strip()
                                    if '-' in part:
                                        start, end = map(int, part.split('-'))
                                        failed_test_list.extend(range(start, end + 1))
                                    else:
                                        failed_test_list.append(int(part))
                                
                                # Add failed tests to the status
                                if failed_test_list:
                                    tests_status["failed"].append(f"{test_file}: {', '.join(map(str, failed_test_list))}")
                            except Exception:
                                pass
                
                # Update total tests counts
                num_tests_failed += failed_tests
                num_tests_passed += (total_tests - failed_tests)
                
                # Track passed tests
                all_tests = list(range(1, total_tests + 1))
                
                # If there are failed tests, determine passed tests
                if failed_tests > 0 and failed_test_list:
                    passed_test_list = [t for t in all_tests if t not in failed_test_list]
                else:
                    passed_test_list = all_tests
                
                # Add passed tests in the same format as failed tests
                tests_status["passed"].append(f"{test_file}: {', '.join(map(str, passed_test_list))}")
        
        return num_tests_passed, num_tests_failed, tests_status

    def run_cmd(self, cmd_tag: str, true_build_src: str, test_dir: str = None) -> TestGuyMetaData:
        commands = self.test_cmds_exps[cmd_tag]['cmd']
        expected = self.test_cmds_exps[cmd_tag]['exp']

        logging.info(f"🔍 Testing {len(commands)} commands - {commands}")
        reports = []
        for cmd in commands:
            logging.info("-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-")
            logging.info(f"🛠️ Running command: {cmd}")
            result = execute_command_in_builder(
                project=self.project,
                command=cmd,
                build_src=self.build_src,
                build_src_docker=test_dir if test_dir else self.build_src_docker
            )

            # 0) Check for timeout
            if result.time_taken > 300:
                logging.info(f"⏰ Command: {cmd} took too long ({result.time_taken} seconds), skipping ...")
                continue
            logging.info(f"⏱️ Command: {cmd} took {result.time_taken} seconds ...")

            # 1) Check for expected errors in the stderr
            stderr = result.stderr.decode("utf-8")
            if all(exp not in stderr for exp in expected):
                test_result = TestGuyMetaData()
                test_check = False

                # 2) Analyze the test command output
                # 3) Create parser for the test command
                if cmd_tag == 'prove':
                    parser_result = self.nginx_unit_tests_parser(result)
                    if parser_result:
                        test_result.num_tests_passed, test_result.num_tests_failed, test_result.tests_status = parser_result
                        test_result.test_parser = {'type': 'nginx_unit_tests_parser', 'args': {}}
                        test_check = True
                else:
                    llm_report = check_test_command_output(result)
                    if llm_report['result'] == 'true':
                        test_result.num_tests_passed, passed_tests_status = self.test_parser(result, llm_report['pass_tag'])
                        test_result.num_tests_failed, failed_tests_status = self.test_parser(result, llm_report['fail_tag'])
                        test_result.tests_status = {'passed': passed_tests_status, 'failed': failed_tests_status}
                        test_result.test_parser = {'type': 'simple_parser', 'args': {'pass_tag': llm_report['pass_tag'], 'fail_tag': llm_report['fail_tag']}}
                        test_check = True
                
                # 4) Check if the test command and parser worked
                if test_check:
                    test_result.test_command_script = cmd
                    test_result.test_command_stdout = result.stdout.decode("utf-8")
                    test_result.test_command_stderr = result.stderr.decode("utf-8")
                    test_result.testing_dir_container_path = str(test_dir) if test_dir else str(self.build_src_docker)
                    test_result.true_build_src = str(true_build_src)
                    logging.info(f"✅ Test command: {cmd} worked ...")
                    logging.info("-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-")

                    # 5) Append the test result to the reports list
                    reports.append(test_result)
                    continue

            logging.info(f"❌ Test command: {cmd} failed ...")
            logging.info("-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-")
        
        # a) Check if any test command was successful
        if len(reports):
            # b) Return the command with the highest number of tests passed
            best_report = max(reports, key=lambda x: x.num_tests_passed)
            logging.info(f"📊 Best test command: {best_report.test_command_script} ...")
            logging.info("------------------------------------------------------")
            return best_report
        logging.info(f"❌ No test command {commands} worked ...")
        logging.info("------------------------------------------------------")
        return TestGuyMetaData()

    def run(self) -> TestGuyMetaData:
        test_result = TestGuyMetaData()
        potential_reports = []
        for true_build_src in self.potential_true_build_srcs:
            logging.info("=======================================================")
            logging.info(f"🔍 Testing {true_build_src} ...")
            self.build_src = self.project_path / 'artifacts' / "built_src" / true_build_src
            self.build_src_docker = Path('/src') / true_build_src

            logging.info(f"🏰 Build source: {self.build_src}")
            logging.info(f"🏰 Build source docker: {self.build_src_docker}")

            # OSS-FUZ Project
            if os.getenv('TASK_SERVICE') == 'True':
                # self.use_task_service = True
                self.use_task_service = False
            else:
                self.use_task_service = False

            self.project = OSSFuzzProject(  
                                            project_id = self.kwargs['project_id'],
                                            oss_fuzz_project_path = self.project_path,
                                            project_source = self.build_src,
                                            use_task_service = self.use_task_service
                                        )
            
            if os.getenv('LOCAL_RUN') == 'True':
                self.project.build_builder_image()
                self.project.build_runner_image()

            # 1a) Check if Makefile is present in the top-level directory
            if os.path.isfile(os.path.join(self.build_src, "Makefile")):
                logging.info("-----------------------------")
                logging.info(f"📁 Makefile found ...")
                logging.info("-----------------------------")

                test_result = self.run_cmd('make', true_build_src)
                if test_result.test_available:
                    potential_reports.append(test_result)
                    logging.info(f"🎉 Found test results in {true_build_src} ...")
                    logging.info("=======================================================")
                    continue

            # 1b) Check if CMakeLists.txt is present in the top-level directory
            if os.path.isfile(os.path.join(self.build_src, "CMakeLists.txt")):
                logging.info("-----------------------------")
                logging.info(f"📁 CMakeLists.txt found ...")
                logging.info("-----------------------------")

                test_result = self.run_cmd('cmake', true_build_src)
                if test_result.test_available:
                    potential_reports.append(test_result)
                    logging.info(f"🎉 Found test results in {true_build_src} ...")
                    logging.info("=======================================================")
                    continue
            
            # 1c) Check if nginx-unit-tests directory is present in the top-level directory
            if os.path.isdir(os.path.join(self.project_path, 'artifacts', 'built_src', 'nginx-unit-tests')):
                logging.info("-----------------------------")
                logging.info(f"📁 nginx-unit-tests directory found ...")
                logging.info("-----------------------------")
                test_dir = Path('/src') / 'nginx-unit-tests'

                test_result = self.run_cmd('prove', true_build_src, test_dir)
                if test_result.test_available:
                    potential_reports.append(test_result)
                    logging.info(f"🎉 Found test results in {true_build_src} ...")
                    logging.info("=======================================================")
                    continue

            # No tests available for the current build source
            logging.info(f"🤡 No test results found in {true_build_src} ...")
            logging.info("=======================================================")

        # a) Check if any test results were found
        if potential_reports:
            # b) Return the best test result
            best_report = max(potential_reports, key=lambda x: x.num_tests_passed)
            logging.info(f"📊 Best test result found by {best_report.test_command_script} ...")
            return best_report
        return TestGuyMetaData()
