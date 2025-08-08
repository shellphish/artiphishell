import os
import re
import logging
from pathlib import Path
from typing import List, Tuple, Dict
from junitparser import JUnitXml, TestSuite, TestCase, Failure, Error

from shellphish_crs_utils.models.crs_reports import RunImageResult
from shellphish_crs_utils.models.testguy import TestGuyParserMetaData

# -----------------------------
# C 'make test' parser
# -----------------------------
def test_parser(result: RunImageResult, tag: str) -> Tuple[int, List[str]]:
    """
    Calculates the number of tests passed by looking at the stdout and stderr of the test command.

    Args:
        result (RunImageResult): The result of the test command.

    Returns:
        int: The number of tests passed.
    """
    count = 0
    stdout = result.stdout.decode("utf-8")
    stderr = result.stderr.decode("utf-8")
    status = []

    for line in stdout.split("\n"):
        if tag in line:
            count += 1
            status.append(line)
    
    for line in stderr.split("\n"):
        if tag in line:
            count += 1
            status.append(line)
    
    return count, status

def simple_parser(**kwargs) -> TestGuyParserMetaData:
    """
    Parses the result of a test command.
    
    Args:
        result (RunImageResult): The result of the test command.
        pass_tag (str): The tag that indicates a test passed.
        fail_tag (str): The tag that indicates a test failed.
    
    Returns:
        int: The number of tests passed.
        dict: A dictionary containing the test results.
    """
    result: RunImageResult = kwargs['result']
    pass_tag: str = kwargs['args']['pass_tag']
    fail_tag: str = kwargs['args']['fail_tag']

    parsed_result = TestGuyParserMetaData()
    try:
        passed, passed_status = test_parser(result, pass_tag)
        failed, failed_status = test_parser(result, fail_tag)
        parsed_result.num_tests_passed = passed
        parsed_result.num_tests_failed = failed
        parsed_result.tests_status = {
            "passed": passed_status,
            "failed": failed_status
        }
        parsed_result.success = True
    except Exception as e:
        logging.error(f"🤡 Error parsing test results: {e}")
    
    return parsed_result

# -----------------------------
# JUnit XML parser
# -----------------------------
def aggregate_xml_results(element, counters):
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
        aggregate_xml_results(child, counters)

def parse_and_output_test_xml(results_dir) -> Dict:
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
            aggregate_xml_results(xml, counters)

    return counters

def junit_parser(**kwargs) -> TestGuyParserMetaData:
    results_dir = Path(kwargs['project_path']) / "artifacts" / "built_src" / kwargs['args']['results_dir']
    parsed_result = TestGuyParserMetaData()
    try:
        results = parse_and_output_test_xml(results_dir)
        parsed_result.num_tests_passed = results['successes']
        parsed_result.num_tests_failed = results['failures']
        parsed_result.tests_status = {
            "passed": results['passed_tests'],
            "failed": results['failed_tests']
        }
        parsed_result.success = True
    except Exception as e:
        logging.error(f"🤡 Error parsing JUnit XML results: {e}")
    
    return parsed_result

# -----------------------------
# nginx test parser
# -----------------------------
def nginx_unit_tests_parser(**kwargs) -> TestGuyParserMetaData:
    result: RunImageResult = kwargs['result']
    stdout = result.stdout.decode("utf-8")
    stderr = result.stderr.decode("utf-8")
    
    # 1) Check if the test summary report is present in the stdout or stderr
    marker = "Test Summary Report\n-------------------"
    if marker in stdout:
        report = stdout.split(marker)[1].strip()
    elif marker in stderr:
        report = stderr.split(marker)[1].strip()
    else:
        return TestGuyParserMetaData(success=False)
    
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
    
    parsed_result = TestGuyParserMetaData()
    parsed_result.num_tests_passed = num_tests_passed
    parsed_result.num_tests_failed = num_tests_failed
    parsed_result.tests_status = tests_status
    parsed_result.success = True
    return parsed_result
