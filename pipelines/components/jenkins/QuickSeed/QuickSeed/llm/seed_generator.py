#!/usr/bin/env python3
import os
import sys
import json
import random
import subprocess
from typing import Dict, Optional, Any
import random
import string

os.chdir(os.path.dirname(__file__))

import agentlib
from agentlib.lib import tools
from agentlib import (
    Agent, PlanExecutor,
    AgentResponse,
    AgentPlan, AgentPlanStep,
    AgentPlanStepAttempt,
    CodeExtractor, WebConsoleLogger,
    Code, CriticReview, JavaCodeExtractor,  LocalObject, SaveLoadObject,
    Field, ObjectParser
)



# @tools.tool
# def read_two_funcs() -> str:
#     """
#     This function will read the code.
#     """
#     funca = read_code(COMMITA)
#     return funca

class SG_Output(SaveLoadObject):
    """
    This object describes the change in two code snippets.
    - key1: value_description.
    - key1: value_description.
    """
    equivalent: str = Field(
        default="No",
        description='return yes or no'
    )
    # details: str = Field(
    #     default="No",
    #     description='describe the result you want here'
    # )


# Create a plan for the agent to follow.
PLAN = AgentPlan(steps=[
    AgentPlanStep(
	llm_model='gpt-4o',
        name='first_step',
        description='Some initial step if you need it',
        #  available_tools=[
        #         find_code
        #         ]
    ),
    AgentPlanStep(
        llm_model='gpt-4o',
        name='generate_seed',
        # Description can contain anything you want to describe the current step
        description='Give ma a seed string',
    ),
    AgentPlanStep(
        llm_model='gpt-4o',
        name='should_we_skip_the_step',
        description='Should we skip the next step? True or False',
    ),
    AgentPlanStep(
        llm_model='gpt-4o',
        name='skipped_this_step',
        description='This step should have been skipped! Now we are all doomed.',
    ),
    AgentPlanStep(
        llm_model='gpt-4o',
        name='some_final_step',
        description='Save data in a text format. ',
        # this would save it in json format. 
        # hack - sometimes gpt changes the keys or adds spaces to json keynames. below is example of how to handle that
        # 'The output MUST be in the following JSON format and use the same keys OR I WILL DIE.\n' +
        #'{"equivalent": "Answer in Yes or No", "details": details_of_changes}'
        output_parser=ObjectParser(SG_Output)
    ),
])

def try_using_seed(seed) -> Optional[CriticReview]:
    # Do whatever you need with the output here and then give feedback based on that
    # I am just going to decide by random
    if random.randint(0,2) == 0:
        return None
    return CriticReview(
        success=False,
        feedback="""
That seed reached a part of the program
def totally_vulnerable_function(foo):
    if foo.startswith('1234567890'):
      os.system(foo)
""")


class SeedGenerator(PlanExecutor[str, str]):
    """
    This agent will follow the steps above.
    """
    __SYSTEM_PROMPT_TEMPLATE__ = 'ha.system.j2'
    __USER_PROMPT_TEMPLATE__ = 'ha.user.j2'

    harness_code: Optional[str]


    def extract_step_attempt_context(
        self,
        step: AgentPlanStep,
        result: AgentResponse
    ) -> str:
        """
        Disable step summarization, and just use the last result from the LLM
        """
        return step.attempts[-1].result

    def extract_final_results(self) -> str:
        """
        Disable final output summarization and just use the last result from the LLM
        """
        steps = self.plan.get_past_steps()
        return steps[-1].attempts[-1].result

    def get_step_input_vars(self, step: AgentPlanStep) -> dict:
        # Template variables for the prompts
        return dict(
            **super().get_step_input_vars(step),
            hello = 'world',
            harness_code = self.harness_code,
        )

    def validate_step_result(
            self,
            step: AgentPlanStep,
            attempt: AgentPlanStepAttempt,
            result
    ) -> bool:
        # Here we can perform validation on the result of the step
        # If we return False, the agent will retry the step with our feedback

        # This first example will take the llm output and pass it into some other part which uses that output and gives CriticFeedback
        if step.name == 'generate_seed':
            print(result)
            assert(isinstance(result, str))
            res = try_using_seed(result)
            if not res:
                return True
            attempt.critic_review = res
            return False

        return super().validate_step_result(step, attempt, result)

    def on_step_success(
            self,
            step: AgentPlanStep,
            result
    ):
        """
        This is just an example of how you could conditionally skip a step if you wanted.
        """
        if step.name == 'should_we_skip_the_step':
            print(result)
            assert(isinstance(result, str))
            if 'true' in result.lower():
                # Skip over the next step
                self.plan.current_step += 1

        return super().on_step_success(step, result)

def main(some_dir, use_model_name):

    # Path to save agent data to
    # agent_path = '/tmp/test_agent.json'
    # if you don't care about saving the agent data, you can just use a temporary file
    random_filename=''.join(random.choice(string.ascii_letters + string.digits) for _ in range(12))
    agent_path = f'/tmp/{random_filename}.json'

    plan = PLAN.save_copy()

    agent: SeedGenerator = SeedGenerator.reload_id_from_file_or_new(
        agent_path,
        goal='yolo',
        plan=plan,
        some_dir=some_dir,
        use_model_name=use_model_name
        
    )

    agent.use_web_logging_config()

    agent.warn(f'========== Agents plan ==========\n')
    print(agent)
    print(agent.plan)

    agent.warn(f'========== Running agent ==========\n')

    res = agent.invoke()
    print(res)


if __name__ == '__main__':
    some_dir = ''
    use_model_name = 'gpt-4o'
    main(some_dir, use_model_name)




