import os
import logging
from typing import Tuple
from pathlib import Path
from junitparser import JUnitXml, TestSuite, TestCase, Failure, Error

from .utils.helpers import execute_command_in_builder, get_build_src_java
from shellphish_crs_utils.models.crs_reports import RunImageResult
from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject
from shellphish_crs_utils.models.testguy import TestGuyMetaData

class Tester4Java:
    def __init__(self, **kwargs):
        self.kwargs = kwargs
        
        ### PATHS ###
        self.project_path = Path(self.kwargs['project_path'])
        # dynamic path to the project source code
        self.potential_true_build_srcs = get_build_src_java(self.project_path)

    def aggregate_xml_results(self, element, counters):
        """
        Recursively aggregates test statistics from JUnit XML elements.
        Handles both TestSuite and TestCase objects, and collects details of failed tests.
        """
        # If element is a TestSuite, accumulate its attributes
        if isinstance(element, TestSuite):
            # Note: TestSuite attributes might not sum up correctly when nested; we rely on TestCase-level counting for accuracy.
            # However, we still process nested suites within a suite.
            pass

        # If element is a TestCase, process its outcome
        elif isinstance(element, TestCase):
            counters['tests'] += 1

            # Check if the test case is marked as skipped i.e., tests that are not counted as successes even if they didn't fail or error
            is_skipped = False
            if getattr(element, 'skipped', False):
                counters['skipped'] += 1
                is_skipped = True

            # Check results attached to this TestCase for failure or error information
            test_failed = False
            for result in element:
                if isinstance(result, Failure):
                    counters['failures'] += 1
                    test_failed = True
                    # Record failure details: (class name, test name, type, message)
                    counters['failed_tests'].append(f"Classname: {element.classname}\n" \
                                                    f"Name: {element.name}\n" \
                                                    f"Type: failure\n" \
                                                    f"Message: {result.text}")
                elif isinstance(result, Error):
                    counters['errors'] += 1
            
            # If the test case neither failed nor was skipped, count it as a success
            if not test_failed and not is_skipped:
                counters['successes'] += 1
                # Record success details: (class name, test name)
                counters['passed_tests'].append(f"Classname: {element.classname}\n" \
                                                f"Name: {element.name}")

        # Safely iterate over children if possible
        try:
            children = list(element)
        except TypeError:
            children = []

        for child in children:
            self.aggregate_xml_results(child, counters)

    def parse_and_output_test_xml(self, results_dir) -> dict:
        # Initialize counters for summary, including successes and a list for failed tests
        counters = {
            'tests': 0,
            'failures': 0,
            'errors': 0,
            'skipped': 0,
            'successes': 0,
            'passed_tests': [],  # List to store details of passed tests
            'failed_tests': []  # List to store details of failed tests
        }

        # Iterate over XML files in the results directory
        for filename in os.listdir(results_dir):
            if filename.endswith('.xml'):
                file_path = os.path.join(results_dir, filename)
                # Parse the XML file using junitparser
                xml = JUnitXml.fromfile(file_path)
                # Aggregate results from the parsed XML tree
                self.aggregate_xml_results(xml, counters)

        return counters
    
    def process_results_dir(self, results_dir: Path) -> Path:
        return os.path.relpath(results_dir, self.project_path / 'artifacts' / 'built_src')

    def gradlew_test(self) -> Tuple[str, RunImageResult, str, dict]:
        # Execute 'gradlew test' in the provided quartz project directory
        command = "./gradlew test"
        result = execute_command_in_builder(
            self.project, 
            command, 
            self.build_src, 
            self.build_src_docker
        )

        # Traverse all subdirectories in project_path to find 'build/test-results/test'
        results_dir, test_results = None, None
        for root, _, _ in os.walk(self.build_src):
            potential_dir = os.path.join(root, 'build', 'test-results', 'test')
            if os.path.isdir(potential_dir):
                results_dir = potential_dir
                logging.info(f"🎯 Gradlew - Found build/test-results/test in {results_dir}")
                test_results = self.parse_and_output_test_xml(results_dir)

        # Check if the results directory was found
        if not results_dir:
            logging.info("🤡 Gradlew - Results directory 'build/test-results/test' not found in any subdirectory of the project path.")

        if not test_results:
            logging.info("🤡 Gradlew - No test results found in 'build/test-results/test'.")
        
        return command, result, self.process_results_dir(results_dir), test_results

    def mvn_test(self) -> Tuple[str, RunImageResult, str, dict]:
        # Get the MVN environment variable
        command = "$MVN test"
        result = execute_command_in_builder(
            self.project, 
            command, 
            self.build_src, 
            self.build_src_docker
        )

        # Traverse all subdirectories in project_path to find 'target/surefire-reports'
        results_dir, test_results = None, None
        for root, _, _ in os.walk(self.build_src):
            potential_dir = os.path.join(root, 'target', 'surefire-reports')
            if os.path.isdir(potential_dir):
                results_dir = potential_dir
                logging.info(f"🎯 MVN - Found 'target/surefire-reports' in {results_dir}")
                test_results = self.parse_and_output_test_xml(results_dir)

        # Check if the results directory was found
        if not results_dir:
            logging.info("🤡 MVN - Results directory 'target/surefire-reports' not found in any subdirectory of the project path.")
        
        if not test_results:
            logging.info("🤡 MVN - No test results found in 'target/surefire-reports'.")
        
        return command, result, self.process_results_dir(results_dir), test_results

    def run(self) -> dict:
        potential_reports = []
        for true_build_src in self.potential_true_build_srcs:
            logging.info("----------------------------------")
            logging.info(f"🔍 Testing {true_build_src} ...")
            self.build_src = self.project_path / 'artifacts' / 'built_src' / true_build_src
            self.build_src_docker = Path('/src') / true_build_src
            
            # OSS-FUZ Project
            if os.getenv('TASK_SERVICE') == 'True':
                self.use_task_service = True 
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

            # Check if pom.xml exists
            pom_path = os.path.join(self.build_src, 'pom.xml')
            # Check if gradlew exists
            gradlew_path = os.path.join(self.build_src, 'gradlew')

            if os.path.isfile(pom_path):
                cmd, result, results_dir, test_results = self.mvn_test()
            elif os.path.isfile(gradlew_path):
                cmd, result, results_dir, test_results = self.gradlew_test()
            else:
                logging.info(f'👎 No pom.xml or gradlew files found ...')
                continue

            # ⏰ Check for timeout
            if result.time_taken > 300:
                logging.info(f"⏰ Command: {cmd} took too long ({result.time_taken} seconds), skipping ...")
                continue
            logging.info(f"⏱️ Command: {cmd} took {result.time_taken} seconds ...")

            if results_dir and test_results:
                if test_results['successes'] > 0:
                    potential_reports.append((result, results_dir, test_results, true_build_src))
                    logging.info(f"🎉 Found test results in {true_build_src} ...")
                else:
                    logging.info(f"🤡 No successfull test results found in {true_build_src} ...")
            else:
                logging.info(f"🤡 No test results found in {true_build_src} ...")
            logging.info("----------------------------------")

        # 1) If no potential reports were found, return an empty TestGuyMetaData object
        if not potential_reports:
            return TestGuyMetaData()
        # 2) If multiple potential reports were found, return the one with the most successes
        if len(potential_reports) > 1:
            result, results_dir, test_results, build_src = max(potential_reports, key=lambda x: x[3]['successes'])
        # 3) If only one potential report was found, return it
        else:
            result, results_dir, test_results, build_src = potential_reports[0]

        # Make a TestGuyMetaData object
        testguy_report = TestGuyMetaData()
        testguy_report.num_tests_passed = test_results['successes']
        testguy_report.num_tests_failed = test_results['failures']
        testguy_report.tests_status = {'passed': test_results['passed_tests'], 'failed': test_results['failed_tests']}
        testguy_report.testing_dir_container_path = str(build_src)
        testguy_report.test_command_script = cmd
        testguy_report.test_command_stdout = result.stdout.decode("utf-8")
        testguy_report.test_command_stderr = result.stderr.decode("utf-8")
        testguy_report.test_parser = {'type': 'junit_parser', 'args': {'results_dir': str(results_dir)}}

        logging.info(f"📊 Best test result found in {testguy_report.test_command_script} ...")

        return testguy_report
