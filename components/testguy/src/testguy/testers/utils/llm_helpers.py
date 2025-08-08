import re
from typing import Dict

from agentlib import LLMFunction
from shellphish_crs_utils.models.crs_reports import RunImageResult

def check_test_command_output(result: RunImageResult) -> Dict[str, str]:
    """
    Check if the test command output contains any test results.
    """
    # Inputs for LLM
    output_format = "You MUST output your answer in the following format:\n\n" \
                    "'''<report><result>...</result><pass_tag>...</pass_tag><fail_tag>...</fail_tag></report>'''\n\n" \
                    "<!-- Guidelines for output generation: -->\n" \
                    "1. For <result>, replace the '...' with either 'true' or 'false', depending on whether the test command output contains any test results.\n" \
                    "2. For <pass_tag>, replace the '...' with the tag used to indicate a test passed in the test command output e.g., 'PASS', 'OK', or any other symbol, etc. (ONLY if <result> is 'true')\n" \
                    "3. For <fail_tag>, replace the '...' with the tag used to indicate a test failed in the test command output e.g., 'FAIL', or any other symbol, etc. (ONLY if <result> is 'true')"
    prompt = "You are a software testing expert!\n" \
             "You are given the output of the test command, and " \
             "you need to determine if the test command output contains any test results in either stdout or stderr.\n" \
             "# STDOUT\n'''{{info.stdout}}'''\n" \
             "# STDERR\n'''{{info.stderr}}'''\n\n" \
             "OUTPUT FORMAT:\n{{info.output_format}}"

    # Asking LLM for the response
    response_extracted = False
    retry_itr = 0
    while not response_extracted and retry_itr < 3:
        ask_llm = LLMFunction.create(
                                prompt,
                                model='gpt-4o',
                                use_loggers=True,
                                temperature=0.0
                            )
        response = ask_llm(
            info = dict(
                stdout=result.stdout.decode("utf-8"),
                stderr=result.stderr.decode("utf-8"),
                output_format=output_format
            )
        )
        print(f"LLM Response: {response}")
        
        # Extracting the response
        final_report = {}
        report = re.findall(r"<report><result>(.*?)</result><pass_tag>(.*?)</pass_tag><fail_tag>(.*?)</fail_tag></report>", response, re.DOTALL)
        if report:
            try:
                final_report['result'] = report[0][0]
                final_report['pass_tag'] = report[0][1]
                final_report['fail_tag'] = report[0][2]
                response_extracted = True
            except Exception as e:
                retry_itr += 1
        else:
            retry_itr += 1
    
    return final_report
