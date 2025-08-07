#!/usr/bin/python3
import os
import re
import sys
import json
import glob
import shutil
import random
import string
import subprocess
import argparse
import pathlib
import random
import string

from typing import Dict, Optional, List

os.chdir(os.path.dirname(__file__))

import agentlib
from agentlib.lib import tools
from agentlib import (
    Agent, PlanExecutor,
    AgentResponse,
    AgentPlan, AgentPlanStep,
    AgentPlanStepAttempt,
    CodeExtractor, WebConsoleLogger,
    tools, LocalObject, SaveLoadObject,
    Field, ObjectParser, CriticReview, JavaCodeExtractor
)

HARNESS_FILE = "/tmp/harness.java"
# utils

def read_code(target_harness) -> str:
    """
    This function will read the code.
    """
    with open(f'{target_harness}', 'r') as f:
        source = f.read()
    # regex = r"(?s)//.*?$|/\*.*?\*/"
    regex = r"(?s)(//.*?$|/\*.*?\*/)[\r\n]*"

    java_code_without_comments = re.sub(regex, "", source, 0, re.MULTILINE)

    print(java_code_without_comments)
    return java_code_without_comments

def write_file(filename, code):
    with open(filename, 'w') as w:
        w.write(code)

@tools.tool
def find_code() -> str:
    """
    This function will read the code.
    """
    with open(HARNESS_FILE, 'r') as f:
        source = f.read()
    regex = r"(?s)(//.*?$|/\*.*?\*/)[\r\n]*"

    java_code_without_comments = re.sub(regex, "", source, 0, re.MULTILINE)

    return java_code_without_comments

def find_files(directory, pattern):
    return glob.glob(os.path.join(args.srcdir, '**', pattern), recursive=True)

def gpt_output_verifier(output, expected_keys):

    verification_result = {
        'verified': False,
        'message': ''
    }

    try:
        data = json.loads(output.strip('```json').strip('```').strip())
        if not isinstance(data, dict):
            verification_result = {
                'verified': False,
                'message': "The output is not a valid dictionary."
            }

        current_keys = set(data.keys())
        missing_keys = [key for key in expected_keys if key not in current_keys]

        if missing_keys:
            verification_result = {
            'verified': False,
            'message': f"Missing keys in the output: {', '.join(missing_keys)}. Expected all keys: {', '.join(expected_keys)}"
            }
        else:
            verification_result = {
                'verified': True,
                'message': "Output is verified and contains all expected keys."
            }

        if verification_result['verified']:
            return data, verification_result
        else:
            return None, verification_result

    except json.JSONDecodeError as e:
        return f"Failed to parse JSON: {str(e)}"
    except Exception as e:
        return f"An error occurred: {str(e)}"


# Updated harness code verifier!

# For future: This goes away if we can build the harness code with build.sh
def find_build_command(run_internal_file, classname, srcdir):
    #with open(run_internal_file, 'r') as f:
        #lines = f.readlines()
    #for line in lines:

        #if classname in line and 'javac' in line:
    line = "javac -cp $SRC/easy-test/build/ PipelineCommandUtilPovRunner.java"
    line = line.replace("$SRC", f'{srcdir}/src').strip()
    line = line.replace(f"{classname}", f"/tmp/{classname}")

    return line

def code_verifier(srcdir, code_updater_output, tmpdir):
    try:
        classname = code_updater_output.get('class_name', None)
        code = code_updater_output.get('updated_code', None)

        # hack
        # for jenkins/aixcc projects we look for run_internal.sh file
        # for oss projects we look in /out directory because oss-fuzz projects dump all classfiles and jars in /out directory after building it
        run_internal_file = find_files(srcdir, 'run_internal.sh')
        if run_internal_file:
            run_internal_file = run_internal_file[0]
            build_command = find_build_command(run_internal_file, classname, srcdir)
        else:

            cname = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(10))
            copy_jazzer_result = subprocess.run([f'docker run -d --name {cname} -it aixcc-jazzer-1-id_1 /bin/bash'], shell=True, capture_output=True)
            if copy_jazzer_result.returncode == 0:
                copying_res = subprocess.run([f'docker cp {cname}:/classpath/jazzer/jazzer_standalone_deploy.jar {tmpdir}/out/'], shell=True, capture_output=True)
                if copying_res.returncode == 0:
                    stop_res = subprocess.run([f'docker stop {cname}'], shell=True, capture_output=True)
                    if stop_res.returncode == 0:
                        rm_res = subprocess.run([f'docker rm {cname}'], shell=True, capture_output=True)
                        print("Successfully copied jazzer_standalone_deploy.jar to out/ directory")
                        jar_directory = f"{tmpdir}/out/"
                        classpath = ':'.join(subprocess.getoutput(f"echo {jar_directory}*.jar").split())
                        build_command = f"javac -cp \"{classpath}\" /tmp/{classname}.java"

        with open(f'/tmp/{classname}.java', 'w') as f:
            f.write(code)
        out = subprocess.run([build_command], shell=True, text=True, capture_output=True)
        if out.stderr:
            return False, str(out.stderr)
        else:
            return True, None

    except subprocess.CalledProcessError as e:
        raise Exception(f"Code verification failed: {e}")

# Code updater agent
def code_updater_agent(target_harness, srcdir, tmpdir, modified_target_harness):

    PLAN = AgentPlan(steps=[
        AgentPlanStep(
            llm_model = 'gpt-4-turbo',
            name='code_locator',
            description='Read the java source file and remember it for later steps.',
            available_tools=[
                find_code
                ]
        ),

        AgentPlanStep(
        llm_model = 'gpt-4-turbo',
        name='modify_file_read',
        description='Using the provided Java code below, replace any locations retrieving input (e.g. FileReader, FileInputStream, BufferedReader, DataInputStream, etc...) with the argument passed to the fuzzerTestOneInput method.\n'
                    "If no locations are found, do not modify the code.\n" +
                    "New comments are not necessary\n" +
                    "Patch out any obvious checks that would gate the function from being fuzzed.\n" +
                    "You are only allowed to make changes to the body of the code. Do not ever modify the class, method, or method signature."
        ),
        AgentPlanStep(
        llm_model = 'gpt-4-turbo',
        name='modify_env_var',
        description="Using the provided Java code below, replace any locations retrieving system or environment information (e.g. System.getenv(), System.getProperties(), etc...) with the argument passed to the fuzzerTestOneInput method.\n" +
                    "If no locations are found, do not modify the code.\n" +
                    "New comments are not necessary\n" +
                    "Patch out any obvious checks that would gate the function from being fuzzed.\n" +
                    "You are only allowed to make changes to the body of the code. Do not ever modify the class name, method name, or method signature."
        ),

        AgentPlanStep(
            llm_model = 'gpt-4-turbo',
            name='code_verification',
            description='We want to verify the code you modified builds and runs successfully. If it does not, we will provide feedback on what went wrong and you should fix the code.\n' +
             'I will provide you with both original code and updated code\n'+
             'Make sure there is no file access and envirionment variable access from the code that you removed before. \n'+
             'Keep all the imports in java code and class names, method name and signature are still same.'
        ),

        AgentPlanStep(
            llm_model = 'gpt-4-turbo',
            name='save_result',
            description='Give me the complete updated java code and name of the class. Extract them into the structured data schema provided.' +
                        '\nThe output MUST be in the following JSON format and use the same keys OR I WILL DIE.\n' +
                        '{"class_name": "PUT_THE_CLASSNAME_HERE", "updated_code": "PUT_THE_NEW_CODE_HERE"}',
            #TODO: add functionality for JavaCodeExtractor in agentlib
            output_parser=ObjectParser(HarnessUpdater)
        )
        ])

    # agent_path = '/tmp/harness_updater_agent.json'
    random_filename=''.join(random.choice(string.ascii_letters + string.digits) for _ in range(10))
    agent_path = f'{tmpdir}/{random_filename}.json'
    plan = PLAN.save_copy()
    SOURCE = read_code(target_harness)
    agent: HarnessModifier = HarnessModifier.reload_id_from_file_or_new(
        agent_path,
        plan=plan,
        goal='Update harness code',
        source=SOURCE,
        srcdir=srcdir,
        tmpdir=tmpdir,
        modified_target_harness=modified_target_harness
    )

    agent.plan.sync_steps(PLAN.steps)
    agent.use_web_logging_config(clear=True)
    agent.warn(f'========== Agents plan ==========\n')
    agent.warn(f'========== Running agent ==========\n')
    res = agent.invoke()
    return res


# TODO: after JavaCodeExtractor is added to agentlib, update this
class HarnessUpdater(SaveLoadObject):
    """
    This object describes the updated harness code.
    - updated_code: The complete updated Java code.
    - class_name: The name of the class in the Java code.
    """

    updated_code: str = Field(
        default="No",
        description='Save the complete updated Java Code to a file.'
    )
    class_name: str = Field(
        default="No",
        description='The name of the class in the Java code.'
    )

class HarnessModifier(PlanExecutor[str, str]):
    """
    This agent will follow the steps above.
    """
    __SYSTEM_PROMPT_TEMPLATE__ = 'harness_modifier.system.j2'
    __USER_PROMPT_TEMPLATE__ = 'harness_modifier.user.j2'

    source: Optional[str]
    counter: int = 0
    srcdir: str
    tmpdir: str

    def get_step_input_vars(self, step: AgentPlanStep) -> dict:
        return dict(
            **super().get_step_input_vars(step),
            source = self.source,
            srcdir = self.srcdir,
            tmpdir = self.tmpdir,
            modified_target_harness = self.modified_target_harness
        )
    def process_step_result(
            self,
            step: AgentPlanStep,
            attempt: AgentPlanStepAttempt
    ):
        return super().process_step_result(step, attempt)


    def validate_step_result(
            self,
            step: AgentPlanStep,
            attempt: AgentPlanStepAttempt,
            result
    ) -> bool:

        if step.name == 'code_verification':
            assert isinstance(result, str), "No code returned by the agent"
            code_updater_output, verification_result = gpt_output_verifier(result, ['class_name', 'updated_code'])
            verified, errors = code_verifier(self.srcdir, code_updater_output, self.tmpdir)
            if not verified:
                if self.counter == 0:
                    attempt.critic_review = CriticReview(
                        success=False,
                        feedback=errors
                    )
                    self.counter += 1
                    return False
            else:
                print("Code verification passed!")
                code = code_updater_output.get('updated_code', None)
                if code and 'fuzzerTestOneInput' in code:
                    write_file(f'{self.modified_target_harness}', code)


        return super().validate_step_result(step, attempt, result)


def main(args):

    target_harness = args.target_harness
    assert isinstance(target_harness, pathlib.Path), "Please provide a valid path"
    shutil.copy(target_harness, HARNESS_FILE)
    res = code_updater_agent(target_harness, args.srcdir, args.tmpdir, args.modified_target_harness)
    print(res)



if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--target_harness", type=pathlib.Path, help="Target harness filepath")
    parser.add_argument("--modified_target_harness", type=pathlib.Path, help="modified target harness filepath")
    '''
    Assumption: that run_internal.sh will have the run_pov() function from which we find build commands.
    In ideal case we should be able to build the harness code and with build.sh
    '''
    parser.add_argument('--srcdir', type=str, help='src directory path')
    parser.add_argument('--tmpdir', type=str, help='tmp directory path with jazzer stuff')

    args = parser.parse_args()

    assert args.target_harness, "Please provide interesting target files path"
    assert args.srcdir, "Please provide src directory path"
    assert args.modified_target_harness, "Please provide outdir path"
    assert args.tmpdir, "Please provide jazzer tmp directory path"
    main(args)


