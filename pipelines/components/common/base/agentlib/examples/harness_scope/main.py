#!/usr/bin/env python3
import os
import sys
import json
import subprocess

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
    Field, ObjectParser
)

class HarnessRequest(SaveLoadObject):
    """
    This object describes a single endpoint which is accessible through the test harness.
    It includes all possible user controlled: headers, query arguments, form/body data, as well as other relevant information.
    """
    endpoint_method: str = Field(
        description='The name of the stapler method which is possible to call from the harness. This will likely be a doXXXXX or some other view/endpoint.'
    )
    endpoint_class: str = Field(
        description='Full class-path of the class which contains the target endpoint method.',
    )
    user_controlled_headers: List[str] = Field(
        description='List of all user-controlled header names for which the value can be set by harness input data.'
    )
    fixed_headers: Dict[str,str] = Field(
        description='Dict of all fixed headers which are always sent with the request. The keys are the header names and the values are the header values.'
    )
    user_controlled_query_args: Dict[str,str] = Field(
        description='Dict of all user-controlled query arguments. The keys are the query argument names and the values are the types of the query arguments (string, int, etc).'
    )
    fixed_query_args: Dict[str,str] = Field(
        description='Dict of all fixed query arguments which are always sent with the request. The keys are the query argument names and the values are the query argument values.'
    )
    form_body_type: Optional[str] = Field(
        description='If relevant, this should be the type of the form body, for example json or form-urlencoded, etc. If there is no body, this should be None.'
    )
    user_controlled_form_data: Dict[str,str] = Field(
        description='Dict of all user-controlled form data key-values. The keys are the form data names and the values are the types of the form data (string, int, json list/object, etc).'
    )
    fixed_form_data: Dict[str,str] = Field(
        description='Dict of all fixed form data key-values which are always sent with the request. The keys are the form data names and the values are the form data values.'
    )
    permissions: List[str] = Field(
        description='Include any jenkins permissions which have been granted to the request. If a permission was taken away, do not include it.'
    )

class AllPossibleHarnessRequests(LocalObject):
    """
    This object contains an exhaustive list all possible harness real or mock request endpoint which can be made from the harness via controlled user input to the harness.
    """
    requests: List[HarnessRequest] = Field(
        description='Details for each endpoint reachable from the harness. This should include all possible user controlled headers, query arguments, form data, and other relevant information for each endpoint, even if that information is duplicated between endpoints. It is most important to get it correct.'
    )
    

@tools.tool
def display_harness_java_class_file(class_name: str) -> str:
    """Find the java file that contains the class definition for the given class name. Only use on harness related classes, not jenkins classes"""

    # TODO more ways to locate the harness file
    for f in os.listdir('./harness_src'):
        if class_name in f: # XXX substring match is not ideal
            with open(f'./harness_src/{f}', 'r') as f:
                return f.read()
    return f'Could not find a file with the class name {class_name}'


# Create a plan for the agent to follow.
PLAN = AgentPlan(steps=[
    AgentPlanStep(
        llm_model = 'gpt-4-turbo',
        description='Locate the java source file which processes the actual POV data after it is loaded by the provided "Runner" or "Harness" class and display it',
        available_tools=[
            display_harness_java_class_file
        ]
    ),
    AgentPlanStep(
        llm_model = 'claude-3-opus',
        description=open('./prompts/steps/initial_analysis.md').read()
    ),
    AgentPlanStep(
        llm_model = 'claude-3-opus',
        description='Read the code again to determine if you missed anything. It is very important that you have exhaustively identified every endpoint that can be called with user-controlled data through this harness.'
    ),
    AgentPlanStep(
        llm_model = 'claude-3-opus',
        description=open('./prompts/steps/define_pov_input.md').read()
    ),
    AgentPlanStep(
        llm_model = 'claude-3-opus',
        description=open('./prompts/steps/input_to_pov.md').read()
    ),
    AgentPlanStep(
        llm_model = 'claude-3-opus',
        description=open('./prompts/steps/request_analysis.md').read()
    ),
    AgentPlanStep(
        llm_model = 'gpt-4-turbo',
        description='Take all the identified request information and extract them into the provided structured data schema.',
        output_parser=ObjectParser(AllPossibleHarnessRequests)
    )
])

class JenkinsHarnessExtractor(PlanExecutor[str, str]):
    __SYSTEM_PROMPT_TEMPLATE__ = 'harness.system.j2'
    __USER_PROMPT_TEMPLATE__ = 'harness.user.j2'

    harness_source: str

    def get_step_input_vars(self, step: AgentPlanStep) -> dict:
        # Template variables for the prompts
        return dict(
            **super().get_step_input_vars(step),
            harness_source = self.harness_source,
        )

    def process_step_result(
            self,
            step: AgentPlanStep,
            attempt: AgentPlanStepAttempt
    ):
        return super().process_step_result(step, attempt)

HARNESS_SOURCE = '''
import java.io.FileInputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

public class PipelineCommandUtilPovRunner {
    public static void fuzzerTestOneInput(byte[] _data) throws Throwable {
        String filename = System.getenv("POV_FILENAME");
        if (null == filename) {
            System.err.println("environment variable `POV_FILENAME` not set");
            System.exit(1);
        }

        FileInputStream f = new FileInputStream(filename);
        byte[] arr = f.readAllBytes();

        PipelineCommandUtilFuzzer.fuzzerTestOneInput(arr);
    }
}
'''

def main():
    agent_path = '/tmp/harness_scope.json'
    plan = PLAN.save_copy()

    agent: JenkinsHarnessExtractor = JenkinsHarnessExtractor.reload_id_from_file_or_new(
        agent_path,
        plan=plan,
        goal='Figure out what parts of the system we are able to control with the input data to the provided fuzzing harness',
        harness_source=HARNESS_SOURCE
    )

    agent.plan.sync_steps(PLAN.steps)

    agent.use_web_logging_config(clear=True)

    agent.warn(f'========== Agents plan ==========\n')
    print(agent)
    print(agent.plan)

    agent.warn(f'========== Running agent ==========\n')

    res = agent.invoke()
    print(res)

if __name__ == '__main__':
    main()